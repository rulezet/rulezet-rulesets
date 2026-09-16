rule sha512_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b7da843eec64c93cb7bbee2e84e7f530bb7c9b637f0286fe5a6edc72a61a6e2193c45884fd6b8e13cb319f29d602315c4bcf70c3f74ac22224f3aace6e1f20ae"
    $a3="b7da843eec64c93cb7bbee2e84e7f530bb7c9b637f0286fe5a6edc72a61a6e2193c45884fd6b8e13cb319f29d602315c4bcf70c3f74ac22224f3aace6e1f20ae"
    $a4="8b580aa9570c124939c6aab9643dbce5dfaddec21728a2a39cc29c4220c052804f8196d7e653d1eb9183624ed002798c29cd36a96e04281dd90ddf13d0f1c670"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="12388bf1485b9e6b8337c8b7be09d14aaa57b146bd7ff4dbfaed71896f9bf9c69205a391d7559a1fa2e7d765d51170d2643b1ad1e4ca94187ff0dfaaf5eb62be"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a9="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a10="2598231ed04d6570f183dd24a9d01e7a0bd3fc709841451ee3475308f3256663fb1cebb744b52ff8392375cb45074fd394a9604e20ab33c6e94a4e75f1fe22a6"
    $a11="2598231ed04d6570f183dd24a9d01e7a0bd3fc709841451ee3475308f3256663fb1cebb744b52ff8392375cb45074fd394a9604e20ab33c6e94a4e75f1fe22a6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}