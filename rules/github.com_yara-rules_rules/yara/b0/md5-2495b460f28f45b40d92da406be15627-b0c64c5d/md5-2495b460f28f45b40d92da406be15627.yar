rule md5_2495b460f28f45b40d92da406be15627 {
    strings: $ = "$dez = $pwddir.\"/\".$real;copy($uploaded, $dez);"
    condition: any of them
}