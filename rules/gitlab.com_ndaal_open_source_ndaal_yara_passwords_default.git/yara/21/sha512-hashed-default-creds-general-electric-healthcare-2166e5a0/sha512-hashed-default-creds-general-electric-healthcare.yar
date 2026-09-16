rule sha512_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a2="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a5="b293f5f9497a37b0ee2fa78ba297653ceef80af78433b5822438c44dc25d7d5e7c14b63c162eb5dd119f276266119e856328c6fa9d854b974e9483813956ad67"
    $a6="8f08246f7e2ea04f82ae424b086dbc91fa829507ad61f84553c0a533978561b7f9ebe04dae055fe95e9b67351fb89dd224b0127caf1c0149ce46f02677814486"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="af10118672e49e03993ffc4d67137e23fced75779299fdd8603cfed03349acc6ddf5cf14644f106c09143792698cfe38cba2fc68f6d8ad7109860b8b225b808d"
    $a9="a81ded4d8247627ff6cf7b9fdfd760efc97eaa055447bdc9c26f3c5e975c2c25ca6dc1a2eea3b331a21529d4416642ff2b8da079a19d1df0664bef1304bad399"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}