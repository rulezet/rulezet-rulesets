rule sha384_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e765d85612d2fb2d4313c8bb5dcdb9947631ee8c0c30216ef7bf4fe8cc67cee8989362566781b0d58a923675b8109c96"
    $a1="e765d85612d2fb2d4313c8bb5dcdb9947631ee8c0c30216ef7bf4fe8cc67cee8989362566781b0d58a923675b8109c96"
    $a2="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
    $a3="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}