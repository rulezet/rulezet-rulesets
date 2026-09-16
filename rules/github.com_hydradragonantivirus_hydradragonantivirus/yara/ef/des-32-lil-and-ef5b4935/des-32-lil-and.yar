rule DES__32_lil_AND_ {
  strings:
    $a0 = { 0f 0f 0f 0f [0-20] ff ff 00 00 [0-20] 33 33 33 33 [0-20] ff 00 ff 00 [0-20] 55 55 55 55 }

  condition:
    $a0
}