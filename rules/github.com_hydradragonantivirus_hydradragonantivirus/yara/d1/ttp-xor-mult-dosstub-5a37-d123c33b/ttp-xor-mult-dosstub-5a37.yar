rule TTP_XOR_MULT_DOSStub_5a37 {
  strings:
    $key_5a37 = { 0e 5f [2] 7a 47 [2] 3d 45 [2] 7a 54 [2] 34 58 [2] 38 52 [2] 2f 59 [2] 34 17 [2] 09 }

  condition:
    any of them
}