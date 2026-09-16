rule sha256_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9"
    $a5="4ca1018f8f72fc8f22b13cdbf8a44acd2b1e406d9f6dbf946006ba79871c8813"
    $a6="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    $a7="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a8="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a9="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a10="b1601f694b9d336c35fc456de5697dfde5e1b1ce4e8c40766fb6cb763aba91c7"
    $a11="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a12="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a13="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a14="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a15="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a16="fa0794c0cd75edf9b0c7356d2204953cb4dc76ab09b74b815ce1a75a86d08034"
    $a17="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a18="8e1f26139c47388ee05a3aa84fc04a78eac158fd4260ec90f2773ae11a49fc4a"
    $a19="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a20="8e1f26139c47388ee05a3aa84fc04a78eac158fd4260ec90f2773ae11a49fc4a"
    $a21="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a22="c16e8324ec510723c3370e590d8f4501e216b427b37fd5ef09ebba78deb12112"
    $a23="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}