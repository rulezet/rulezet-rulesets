rule TTP_XOR_MULT_DOSStub_1a37 {
  strings:
    $key_1a37 = { 4e 5f [2] 3a 47 [2] 7d 45 [2] 3a 54 [2] 74 58 [2] 78 52 [2] 6f 59 [2] 74 17 [2] 49 }

  condition:
    any of them
}