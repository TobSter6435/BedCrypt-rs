use std::fs::{self, File};
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use rand::RngCore;

use rusqlite::{params, Connection};

use dialoguer::Password;
use figlet_rs::FIGlet;
use indicatif::{ProgressBar, ProgressStyle};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
struct State {
    master_password: String,
    user_name: String,
}

fn ascii_art(text: &str) {
    let standard_font = FIGlet::standard().unwrap();
    let ascii_art = standard_font.convert(text).unwrap();
    println!("{}", ascii_art);
}

fn generate_uuid() -> String {
    let uuid = Uuid::new_v4();
    uuid.to_string()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn derive_key(master_password: &str, salt_bytes: &[u8]) -> [u8; 32] {
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt_bytes, &mut key_bytes)
        .expect("Schlüsselableitung fehlgeschlagen");
    key_bytes
}

fn open_db() -> Connection {
    let conn = Connection::open("database.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS operations (
        uuid TEXT PRIMARY KEY,
        input_path TEXT NOT NULL,
        output_path TEXT NOT NULL,
        operation_type TEXT NOT NULL,
        status TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        salt TEXT NOT NULL
    )",
        [],
    )
    .unwrap();
    conn
}

fn log_operation(
    conn: &Connection,
    uuid: &str,
    input_path: &str,
    output_path: &str,
    operation_type: &str,
    status: &str,
    salt_hex: &str,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    conn.execute(
        "INSERT INTO operations (uuid, input_path, output_path, operation_type, status, start_time, end_time, salt)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![uuid, input_path, output_path, operation_type, status, now.clone(), now, salt_hex],
    )
    .unwrap();
}

fn prompt(text: &str) -> String {
    print!("{}", text);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}

fn encrypt_file(state: &State) {
    println!();
    let input_path = prompt("Enter the path of the file to encrypt: ");
    if input_path.is_empty() {
        println!("Input path cannot be empty");
        return;
    }

    println!("------------------------------------------------------------------------");
    let raw_bytes = match fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            println!("Could not read input file: {}", e);
            return;
        }
    };

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    pb.set_message("reading file...");
    thread::sleep(Duration::from_millis(600));
    pb.finish_and_clear();

    println!("------------------------------------------------------------------------");
    let output_path = prompt("Enter the path to save the encrypted file: ");
    if output_path.is_empty() {
        println!("Output path cannot be empty");
        return;
    }

    let conn = open_db();

    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt_hex = bytes_to_hex(&salt_bytes);

    let key_bytes = derive_key(&state.master_password, &salt_bytes);
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, raw_bytes.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            println!("Encryption failed");
            return;
        }
    };

    let mut file_out = File::create(&output_path).unwrap();
    file_out.write_all(&nonce_bytes).unwrap();
    file_out.write_all(&ciphertext).unwrap();

    let uuid = generate_uuid();
    log_operation(&conn, &uuid, &input_path, &output_path, "ENCRYPT", "SUCCESS", &salt_hex);

    println!();
    println!("STATUS: [success]");
    println!("UUID: {}", uuid);
    println!("OUTPUT_PATH: {}", output_path);
    println!("Keep this UUID — you need it to decrypt the file again.");
    thread::sleep(Duration::from_millis(600));
    println!();
}

fn decrypt_file(state: &State) {
    println!();
    let uuid_input = prompt("Enter the UUID of the encryption operation to decrypt: ");
    if uuid_input.is_empty() {
        println!("UUID cannot be empty");
        return;
    }

    let conn = open_db();

    let result: Result<(String, String, String), _> = conn.query_row(
        "SELECT input_path, output_path, salt FROM operations
         WHERE uuid = ?1 AND operation_type = 'ENCRYPT' AND status = 'SUCCESS'",
        params![uuid_input],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );

    let (_orig_input_path, encrypted_path, salt_hex) = match result {
        Ok(row) => row,
        Err(_) => {
            println!("No matching successful encryption operation found for this UUID!");
            return;
        }
    };

    println!("Found record — encrypted file: {}", encrypted_path);

    let file_bytes = match fs::read(&encrypted_path) {
        Ok(b) => b,
        Err(e) => {
            println!("Could not read encrypted file at recorded path: {}", e);
            return;
        }
    };

    if file_bytes.len() < 24 {
        println!("Encrypted file is corrupted or too short");
        return;
    }

    let (nonce_bytes, ciphertext) = file_bytes.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    let salt_bytes = hex_to_bytes(&salt_hex);
    let key_bytes = derive_key(&state.master_password, &salt_bytes);
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb.set_message("decrypting...");
    thread::sleep(Duration::from_millis(400));
    pb.finish_and_clear();

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(_) => {
            println!("Decryption failed — wrong master password, wrong UUID, or the file was tampered with.");
            let fail_uuid = generate_uuid();
            log_operation(&conn, &fail_uuid, &encrypted_path, "", "DECRYPT", "FAILURE", &salt_hex);
            return;
        }
    };

    println!("------------------------------------------------------------------------");
    let save_path = prompt("Enter the path to save the decrypted file: ");
    if save_path.is_empty() {
        println!("Output path cannot be empty");
        return;
    }

    if let Err(e) = fs::write(&save_path, &plaintext) {
        println!("Failed to write decrypted file: {}", e);
        return;
    }

    let uuid = generate_uuid();
    log_operation(&conn, &uuid, &encrypted_path, &save_path, "DECRYPT", "SUCCESS", &salt_hex);

    println!();
    println!("STATUS: [success]");
    println!("UUID: {}", uuid);
    println!("OUTPUT_PATH: {}", save_path);
    thread::sleep(Duration::from_millis(600));
    println!();
}

fn show_recent_operations() {
    let conn = open_db();

    let mut stmt = conn
        .prepare(
            "SELECT uuid, operation_type, input_path, output_path, status, start_time
             FROM operations ORDER BY start_time DESC LIMIT 10",
        )
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .unwrap();

    println!("\n------------------------------ Recent Operations ------------------------------");
    println!(
        "{:<36} {:<8} {:<8} {:<10}",
        "UUID", "TYPE", "STATUS", "TIME"
    );
    println!("------------------------------------------------------------------------------");

    let mut any = false;
    for row in rows {
        let (uuid, op_type, input_path, output_path, status, start_time) = row.unwrap();
        any = true;
        println!("{:<36} {:<8} {:<8} {:<10}", uuid, op_type, status, start_time);
        println!("   in:  {}", input_path);
        println!("   out: {}", output_path);
    }

    if !any {
        println!("No operations recorded yet.");
    }
    println!("------------------------------------------------------------------------------\n");

    prompt("Press Enter to continue...");
}

fn login() -> Option<State> {
    println!("<-------------------------------Login------------------------------->");
    println!();

    let user_name = prompt("Enter your user name: ");
    if user_name.is_empty() {
        println!("User name cannot be empty");
        return None;
    }

    println!("------------------------------------------------------------------------");

    let master_password = Password::new()
        .with_prompt("Enter your master password")
        .interact()
        .unwrap();
    let master_password = master_password.trim();

    let conn = Connection::open("database.db").unwrap();

    let db_result: Result<String, _> = conn.query_row(
        "SELECT master_password FROM users WHERE user_name = ?1",
        params![user_name],
        |row| row.get(0),
    );

    let db_password_hash = match db_result {
        Ok(hash) => hash,
        Err(_) => {
            println!("User not found!");
            return None;
        }
    };

    let parsed_hash = PasswordHash::new(&db_password_hash).expect("Failed to parse stored hash");
    let argon2 = Argon2::default();

    if argon2.verify_password(master_password.as_bytes(), &parsed_hash).is_ok() {
        Some(State {
            master_password: master_password.to_string(),
            user_name: user_name.to_string(),
        })
    } else {
        println!("Login failed!");
        None
    }
}

fn register() {
    println!("<-------------------------------Register------------------------------->");
    println!();

    let user_name = prompt("Enter your user name: ");
    if user_name.is_empty() {
        println!("User name cannot be empty");
        return;
    }

    println!("------------------------------------------------------------------------");

    let master_password = Password::new()
        .with_prompt("Enter your master password")
        .with_confirmation("Repeat your master password", "Passwords do not match. Try again.")
        .interact()
        .unwrap();
    let master_password = master_password.trim();

    let conn = Connection::open("database.db").unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT NOT NULL UNIQUE,
        master_password TEXT NOT NULL,
        salt TEXT NOT NULL
    )",
        [],
    )
    .unwrap();

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut rand::thread_rng());

    println!();
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    pb.set_message("Hashing password...");

    let password_hash_string = argon2
        .hash_password(master_password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    thread::sleep(Duration::from_millis(600));
    pb.finish_and_clear();

    conn.execute(
        "INSERT INTO users (user_name, master_password, salt) VALUES (?1, ?2, ?3)",
        params![user_name, &password_hash_string, salt.as_str()],
    )
    .unwrap();

    println!("User {} registered successfully", user_name);
}

fn main() {
    let state = loop {
        ascii_art("BedCrypt-RS");
        thread::sleep(Duration::from_millis(600));

        println!("1. Login");
        println!("2. Register");
        println!("3. Exit");
        println!();

        let choice = prompt("Enter your choice(1, 2, 3): ");

        match choice.parse::<u32>() {
            Ok(1) => {
                if let Some(login_state) = login() {
                    println!("\nWelcome back, {}.\n", login_state.user_name);
                    thread::sleep(Duration::from_millis(600));
                    break login_state;
                }
            }
            Ok(2) => {
                register();
            }
            Ok(3) => {
                println!("Exit");
                std::process::exit(0);
            }
            _ => {
                println!("Invalid choice");
            }
        }
    };

    loop {
        ascii_art("BedCrypt-RS");
        thread::sleep(Duration::from_millis(600));
        println!();
        println!("Welcome {}!\n\nwhat do you want to do?(1,2,3,4)\n", state.user_name);
        println!("1. Encrypt file\n2. Decrypt file\n3. Show recent operations\n4. Exit\n");

        let choice = prompt("");

        match choice.parse::<u32>() {
            Ok(1) => {
                encrypt_file(&state);
            }
            Ok(2) => {
                decrypt_file(&state);
            }
            Ok(3) => {
                show_recent_operations();
            }
            Ok(4) => {
                std::process::exit(0);
            }
            _ => {
                println!("Invalid choice");
            }
        }
    }
}