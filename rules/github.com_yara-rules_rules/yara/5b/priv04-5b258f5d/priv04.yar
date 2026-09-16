rule priv04 {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 strings:
    $varb03 = { 89 DF E8 FB A4 FF FF 83 C3 01 81 FB 00 04 }
    $vard03 = { 66 89 05 7D 5E 00 00 }
     condition:
    1 of them
}