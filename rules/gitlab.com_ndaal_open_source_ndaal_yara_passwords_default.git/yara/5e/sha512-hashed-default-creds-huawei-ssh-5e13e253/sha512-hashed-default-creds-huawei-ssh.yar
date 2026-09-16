rule sha512_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a4="8e8a26e46d810aa1206c7d87f62432f6fbbb5d0a7cc7521e8e33650cf3ac336908c6176d7d2c4769231547f8623ddf265932a42d80d4fa2cb20e5ea5c3c84c90"
    $a5="8e8a26e46d810aa1206c7d87f62432f6fbbb5d0a7cc7521e8e33650cf3ac336908c6176d7d2c4769231547f8623ddf265932a42d80d4fa2cb20e5ea5c3c84c90"
    $a6="868ff9386e3dea32436089cad85f840e26a0c41865b7bba2230c5acab4c01e791f8c606d33cfccd18d44714e147d6df33146a3f706f2cce669276f011219ea17"
    $a7="47d1dac5aa905cf79ba459698cbbb442e7d2f9cd2a012720f1c83fd87457e05b4a4f0794547e673dc0b69c6ba5e7d5958d0c6de304d83a58c142dc11393457c8"
    $a8="b588ab063a67925162377e16a86dd33ced8130b75facd77bf02a8c9bc34ed6c18917ac492107cb38345ecc35a432c5fad4d31c413fca75c2bedd55e46663089f"
    $a9="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a10="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a11="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a12="d27b9b86be2c1ee43c50dcae09b3c18e155748dd5a3624098c87bc933110c57d940b1b81c833c233a35036d9a1f065a0e519976a220ee31f7da2a93b78513edd"
    $a13="d27b9b86be2c1ee43c50dcae09b3c18e155748dd5a3624098c87bc933110c57d940b1b81c833c233a35036d9a1f065a0e519976a220ee31f7da2a93b78513edd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}