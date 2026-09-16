rule md5_4aa900ddd4f1848a15c61a9b7acd5035 {
    strings: $ = "'base'.(128/2).'_de'.'code'"
    condition: any of them
}