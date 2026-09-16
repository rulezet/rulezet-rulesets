rule sha512_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56319d24143b186cc31e9c0d873a8675672e7069bb7f919794d033f3b3e4b37e2b500a11eeb111effe4e61dfe8175ac2c728692cf3d0af8ef1b8bfd9842762c2"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="af6ff415c73a824bfb89739b48f33d71963742d9c8f4aeda504cf58bfb98f1e887c0f0b5e8b189d897368bcd7c240dfce5cb337d55a3b2764d682a6ed6b98423"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="a145800e53a326d880f4b513436e54a0ab41efc8fdd4f038c0edae948e5ae08d2a7077d5bb648415078dda2571fe92c4d6fa2130a80f53d9dd329e7040729e81"
    $a5="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}