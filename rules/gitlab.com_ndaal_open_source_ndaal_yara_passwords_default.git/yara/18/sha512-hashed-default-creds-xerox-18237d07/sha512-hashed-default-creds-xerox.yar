rule sha512_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ee6198ce703bbe1f4d1b590aa4d04595d20dbbcdd8716352ff01435a0c31ac4f10d2d084b3447a7977de1643ea94ba619329ba9938c9364e187c71901f64fa9"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="4cf5a5be41f417cb2087f1f17e44734ae9b1677dc6b0ed3b80de422cc8e5607980ed08334540c15966485db039927bade22d3dedd5fd3b3f7d9743c20310882c"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="a8cebf1698dc14282c507b1e1cfb7f2c9d5216aa7bd0854b50561e02c2b99d9a38945ec0f81e55f9699062b1eac6d0083411c839ba2b27c6a15b494463bc5c73"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="8ee6198ce703bbe1f4d1b590aa4d04595d20dbbcdd8716352ff01435a0c31ac4f10d2d084b3447a7977de1643ea94ba619329ba9938c9364e187c71901f64fa9"
    $a9="22e7e9d85b7fe6004f7b9f3aa592ea9ec9ce098682e8192fa83785f1784c768d1d1ac3b8afcae88666f66aec24739ac133e9d4adc7506f1a5f1f6078cb27c674"
    $a10="33275a8aa48ea918bd53a9181aa975f15ab0d0645398f5918a006d08675c1cb27d5c645dbd084eee56e675e25ba4019f2ecea37ca9e2995b49fcb12c096a032e"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="1eddd7d92d849b0079fb72f1d6bf1741b27de66f86323a8bfe89d819b612dbc650d16057aabcabaadc2841381c3e01562ce0e41676b0ce0fc703826cfa080cf5"
    $a13="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a14="29cd389bf5f205db2d07fda3ca1d59c2b80818cec60ec33a057e33eaa2f93c7f0a2bf1ee097a16813c25c511aae13e7919187c72d48b27195abd506bae8e8d3d"
    $a15="9e3ac18b9783c8085820ab23e368c503ae89bdce981dd601b6415ebd752e8244c065041576085cab6726ed50182f2e1dfa1a93e570dc91148a96315fcbaf477a"
    $a16="66d941a90d78d937c221b6ce8c5d66c1d196d7edc487dede0fc260bb43acd32df1306792683a7c294fa47e3df74a9ca5fad1a20f4bc07e743f2a35bb8590a1e8"
    $a17="982c9dbf38b5f40dbc699765beabd86bd156b7aeb6059173174c983b378985777a41a969d064a4715ecc016923f3eec5fbed71f1034d56e22c115b2179402ddc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}