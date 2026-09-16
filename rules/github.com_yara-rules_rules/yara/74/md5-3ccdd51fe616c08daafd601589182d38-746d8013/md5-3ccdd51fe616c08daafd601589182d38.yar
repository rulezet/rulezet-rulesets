rule md5_3ccdd51fe616c08daafd601589182d38 {
    strings: $ = "eval(xxtea_decrypt"
    condition: any of them
}