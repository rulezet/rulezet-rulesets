rule sha3_512_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b31b10f9c15b871145c2088cce3cffa588d96cc690772ba7363bc701e24fc5af98765f01c72bfe615190436cdfa48583f06eced610a74b1485d0ae2283805cbe"
    $a1="1576de20a88104cc42ef5bceabc041292eb1a93a2498acf32a16294a1866bda98620bd9cbf75041ca98e635987fd1726a60e013291ef516754f8f3e0592cd53d"
    $a2="26526923c588acc54b4f434ebe07ea55052d0c0c0a526312f042523247d7526ffb00bcc910a629c2407df4559872ba3f349bc2170db90e85d63e926b984ca043"
    $a3="f9c0a1522bcf48e876c53c6666cdcbf9483b60dad06a6d10047646ea07355ebe38886371e6085a52aca38ef0a09726a8aebf20d2c721a72a5f13f562dd5d6a80"
    $a4="7c52c75b0869edfc243acc4c0c57b23369ce8c53d69074ecd2e38e432c2ccee1049c2dabf28efbf4a001a3e277c4cd5b325aa836372e71a1c9af5939a0ad6dd2"
    $a5="0cc96602c0f07c08103df6cd6e3ab0823d2fd0283465fff801fc7ba47eca7e5e834d882375a855ffb9e7e480a95a6d1d65c3c77b9289076aa7eae973d4084c12"
    $a6="66ab55371bc9eb2b674b91381afee3d747dda1ed65cbd10cc40ce3a4d9ff69c007f120552056acbf9e50c1b0015fcfcad2cc61bfcd469437825038ad4ab149a1"
    $a7="1f7ce4d6e35c072dbf4ad27424c4609c0623f0b71eedc08129120f7c10102dc4e0e390d1ddc0870970c438a0273750e0ebbadd0fdca0fbdf870fed88da93f1d1"
    $a8="7cd5d5cc14b9654557c099ac4423d6192de8485535f6de53841afb8214dbc0b6a4e63abc44ddf8d0c83d743ecd0a90648ffe6ffa5bfbfd17332afb7d33b68062"
    $a9="5387020bbe4c2b2186aa2d9fc7f42e79e9a73322f26a515dc37380ed8b324fb409f535cccc70a9e97f8e857ef9a0bb2f633a74c2ca80409cf6d10b274606662c"
    $a10="1296b5abc2265fe188d84187df84c4b4d7e672e95aa3a86633e9c58a97f79dcaed9775229734aed3754f169c6b4ed6126bcc8c9802e3858430007a066751e6b8"
    $a11="074631ec072c6777c541bf8d767df7babdb4b00c788e314f09c6eea213fbba7ed1252c5c3e06a0b4be3dd6655d33f6d60f506930af82dd68a366b8150c7f7486"
    $a12="0d6f5396dfa139eb971b1fb8860c753e7a5f11dafa68ae814ba487cce8e4bdd310aac4196259fe1810b38f6db51f427d237ec00c2f63f5a6e1e75f4ee3ecc80d"
    $a13="c6ff872a97f4d8e664d0899821e9ad5421074a15d0c620e2e172c3a230b8dd962598f5e5169deab3e6a8f22d96b9e376272a5a36abec7073e550d2e1d3bbc3d2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}