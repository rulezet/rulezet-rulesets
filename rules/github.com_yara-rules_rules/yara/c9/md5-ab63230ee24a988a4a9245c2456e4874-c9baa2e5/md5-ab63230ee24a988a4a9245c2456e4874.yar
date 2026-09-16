rule md5_ab63230ee24a988a4a9245c2456e4874 {
    strings: $ = "eval(gzinflate(base64_decode(str_rot13(strrev("
    condition: any of them
}