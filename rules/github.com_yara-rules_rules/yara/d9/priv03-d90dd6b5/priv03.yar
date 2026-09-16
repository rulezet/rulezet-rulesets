rule priv03 {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 strings:
    $varb01 = { 41 57 41 56 41 55 41 54 55 53 0F B6 06 }
    $varb02 = { 48 C7 07 00 00 00 00 48 C7 47 08 00 00 }
    $vard01 = { 55 48 89 E5 41 57 41 56 41 55 41 54 53 }
    $vard02 = { 55 48 89 E5 48 C7 47 08 00 00 00 00 48 }
     condition:
    (2 of ($varb*)) or (2 of ($vard*))
}