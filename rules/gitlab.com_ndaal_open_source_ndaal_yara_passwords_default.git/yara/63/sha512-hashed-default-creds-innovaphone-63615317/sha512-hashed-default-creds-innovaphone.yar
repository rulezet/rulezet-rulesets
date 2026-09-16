rule sha512_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7558964b4d5d41193588b68027abba5dff4d0d676619fb60566776be2bb71e22dc4ca1b2bed4eede5b5675328fd16122a479013942a0eb714f081174cd094b4"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="887add6b2e801cd26a7141db688905064d37e71333485cfee7fcfc74fe3057c1509c325821cfc5abe6bf1d4f3bb2c95508639ceb172f2a343c3c7f6c93429873"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="598535b96b94c8bb8608a633367406bc5239955d83cc483b3fbd64c9e6f72f94d079c65f38689c3dd0fa87f7514e380d63958d21d610245dbf1a0dd668b585b2"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="6b9e99be87ea6b47b88b2f1db364d6d65767ab937d47a2d9bd5f199b84526f13dd8a4f683caa5f890faca0a68e70ae3acea5077970a5cf99465d0872bc8b6fc8"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="f5ae6bcd00181012da454092f4168a1f69626c41d7ca1ac6b8e4fc163329bfc1996c49fa0cfc47b124168dc98bf01d7c7eebbe4eead39727ee399a132e261ca9"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}