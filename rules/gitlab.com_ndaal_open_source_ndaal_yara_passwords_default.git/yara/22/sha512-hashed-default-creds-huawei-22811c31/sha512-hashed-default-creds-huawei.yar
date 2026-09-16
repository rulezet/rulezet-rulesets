rule sha512_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="b938b0634d6ff85ef174049ee46c77249c7f73b639b81a5ade062ab8d12e7e6438705d986cb8c80aa3f9935e1cdf2b895f79818c58e8bb64549a50e06e8b271c"
    $a2="1812bf8840e9fbbae06bef58c510f4bff23534655e3fd60e9a62119648027938045fa320d452f46bde45225441670fc3c2bf248baf9f80d253af8833cd6136dd"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="6092d8873082c0cbb4dbe8ba42e596b8c4f11afdbef413947b6cc387c4caed1a5e0e054a4e8e27a656bf6ef7b2d17bd314c03eb4e7686518e5046f05577798ce"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="4a0bb8ffefa17bca8acc4d131a358bfbe26e74a737ba0448b85c015855990cfdc2f1a09283d2d721b03b5d087c6b25a925733178ab986f0751b41110df8027b8"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="7857ccdd456ef829f337a81127a7f42fe3fa7dbe2ee5aad419e66d7f54f029db3569eab3b3e98c07e99f1bcc78a051234970febaf9e33fe8af406fe76adcd23d"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}