use ml_dsa::{MlDsa65, Signature, EncodedVerifyingKey, EncodedSignature, VerifyingKey};
use ml_dsa::signature::Verifier;
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use base64::{Engine as _, engine::general_purpose};
use std::io::Read;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    // 1. Hardcoded base64 verification key
    // Replace this with your actual base64-encoded public key
    let encoded_public_key = "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";
    let decoded_key_bytes = general_purpose::STANDARD.decode(encoded_public_key)?;

    // Create a verification key - using decode() method which properly handles ownership
    let mut key_bytes = [0u8; std::mem::size_of::<EncodedVerifyingKey<MlDsa65>>()];
    let len = std::cmp::min(decoded_key_bytes.len(), key_bytes.len());
    key_bytes[..len].copy_from_slice(&decoded_key_bytes[..len]);

    let encoded_key = EncodedVerifyingKey::<MlDsa65>::from(key_bytes);
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);

    // 2. GitHub repo information
    let owner = "IES-parquesol-package-registry";
    let repo = "registry";

    let client = Client::new();

    // 3. Fetch the latest release from GitHub API
    println!("Fetching latest release information...");
    let releases_url = format!("https://api.github.com/repos/{}/{}/releases/latest", owner, repo);

    let mut response = client.get(&releases_url)
        .header("User-Agent", "GitHub-JSON-Verifier")
        .send()?;

    // Parse the JSON response
    let mut body = String::new();
    response.read_to_string(&mut body)?;
    let release_info: Value = serde_json::from_str(&body)?;

    // 4. Extract release tag and download URLs
    let release_tag = release_info["tag_name"].as_str().ok_or("Could not extract release tag")?;

    // Find the download URLs in the assets or use direct URLs
    let json_url = format!(
        "https://github.com/{}/{}/releases/download/{}/index.json",
        owner, repo, release_tag
    );

    let signature_url = format!(
        "https://github.com/{}/{}/releases/download/{}/sign.sig",
        owner, repo, release_tag
    );

    // 5. Download files
    println!("Downloading JSON from: {}", json_url);
    let json_content = client.get(&json_url).send()?.text()?;

    println!("Downloading signature from: {}", signature_url);
    let signature_bytes = client.get(&signature_url).send()?.bytes()?.to_vec();

    // 6. Convert bytes to signature
    let mut sig_bytes = [0u8; std::mem::size_of::<EncodedSignature<MlDsa65>>()];
    let sig_len = std::cmp::min(signature_bytes.len(), sig_bytes.len());
    sig_bytes[..sig_len].copy_from_slice(&signature_bytes[..sig_len]);

    let encoded_sig = EncodedSignature::<MlDsa65>::from(sig_bytes);
    let signature = Signature::<MlDsa65>::decode(&encoded_sig)
        .ok_or("Failed to decode signature")?;

    // 7. Verify the signature
    println!("Verifying signature...");
    if verifying_key.verify(json_content.as_bytes(), &signature).is_ok() {
        println!("✅ Signature verified successfully!");

        // 8. Parse and process the JSON data
        println!("Processing JSON data...");
        let json_data: Value = serde_json::from_str(&json_content)?;

        // Process packages based on the actual JSON structure
        process_packages(&json_data)?;
    } else {
        println!("❌ Signature verification failed!");
    }

    Ok(())
}

// Process package installation commands based on the JSON structure
fn process_packages(json_data: &Value) -> Result<(), Box<dyn Error>> {
    if let Value::Object(map) = json_data {
        // Print version information if available
        if let Some(version) = map.get("version").and_then(|v| v.as_str()) {
            println!("Package registry version: {}", version);
        }

        println!("\n====== Updating APT Repositories ======");
        let output = Command::new("sudo")
            .args(["apt-get", "update", "-y"])
            .output()?;

        println!("\n====== Updating APT Packages ======");
        let output = Command::new("sudo")
            .args(["apt-get", "upgrade", "-y"])
            .output()?;

        println!("\n====== Updating Flatpak Packages ======");
        let output = Command::new("flatpak")
            .args(["update", "-y"])
            .output()?;

        // Process apt packages
        if let Some(apt_packages) = map.get("apt").and_then(|v| v.as_array()) {
            println!("\n====== Installing APT Packages ======");
            for package in apt_packages {
                if let Some(package_name) = package.as_str() {
                    install_apt_package(package_name)?;
                }
            }
        }

        // Process apt repositories
        if let Some(apt_repos) = map.get("apt-repos").and_then(|v| v.as_array()) {
            println!("\n====== Adding APT Repositories ======");
            for repo in apt_repos {
                if let Some(repo_name) = repo.as_str() {
                    add_apt_repository(repo_name)?;
                }
            }
        }

        // Process flatpak packages
        if let Some(flatpak_packages) = map.get("flatpak").and_then(|v| v.as_array()) {
            println!("\n====== Installing Flatpak Applications ======");
            for package in flatpak_packages {
                if let Some(package_name) = package.as_str() {
                    install_flatpak_package(package_name)?;
                }
            }
        }

        // Process snap packages
        if let Some(snap_packages) = map.get("snap").and_then(|v| v.as_array()) {
            println!("\n====== Installing Snap Applications ======");
            for package in snap_packages {
                if let Some(package_name) = package.as_str() {
                    install_snap_package(package_name)?;
                }
            }
        }

        println!("\nPackage processing completed");
    } else {
        println!("Invalid JSON format: expected object at root level");
    }

    Ok(())
}

// Install an apt package
fn install_apt_package(name: &str) -> Result<(), Box<dyn Error>> {
    println!("Installing apt package: {}", name);
    let output = Command::new("sudo")
        .args(["apt-get", "install", name, "-y"])
        .output()?;

    if output.status.success() {
        println!("✅ Successfully installed {}", name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("❌ Failed to install {}: {}", name, stderr);
    }

    Ok(())
}

// Add an apt repository
fn add_apt_repository(repo: &str) -> Result<(), Box<dyn Error>> {
    println!("Adding apt repository: {}", repo);
    let output = Command::new("sudo")
        .args(["add-apt-repository", repo, "-y"])
        .output()?;

    if output.status.success() {
        println!("✅ Successfully added repository {}", repo);

        // Update apt cache after adding a repository
        println!("Updating apt cache...");
        let update_output = Command::new("sudo")
            .args(["apt-get", "update"])
            .output()?;

        if !update_output.status.success() {
            let stderr = String::from_utf8_lossy(&update_output.stderr);
            println!("⚠️ Warning: Failed to update apt cache: {}", stderr);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("❌ Failed to add repository {}: {}", repo, stderr);
    }

    Ok(())
}

// Install a flatpak package
fn install_flatpak_package(name: &str) -> Result<(), Box<dyn Error>> {
    println!("Installing flatpak application: {}", name);
    let output = Command::new("flatpak")
        .args(["install", name, "-y"])
        .output()?;

    if output.status.success() {
        println!("✅ Successfully installed {}", name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("❌ Failed to install {}: {}", name, stderr);
    }

    Ok(())
}

// Install a snap package
fn install_snap_package(name: &str) -> Result<(), Box<dyn Error>> {
    println!("Installing snap application: {}", name);
    let output = Command::new("sudo")
        .args(["snap", "install", name, "--classic"])
        .output()?;

    if output.status.success() {
        println!("✅ Successfully installed {}", name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("❌ Failed to install {}: {}", name, stderr);
    }

    Ok(())
}

// Helper extension trait to get type names for better output
trait TypeName {
    fn type_name(&self) -> &'static str;
}

impl TypeName for Value {
    fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}