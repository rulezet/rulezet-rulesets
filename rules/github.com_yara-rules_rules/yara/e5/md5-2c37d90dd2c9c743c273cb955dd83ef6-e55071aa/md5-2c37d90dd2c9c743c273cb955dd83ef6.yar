rule md5_2c37d90dd2c9c743c273cb955dd83ef6 {
    strings: $ = "@$_($_REQUEST['"
    condition: any of them
}