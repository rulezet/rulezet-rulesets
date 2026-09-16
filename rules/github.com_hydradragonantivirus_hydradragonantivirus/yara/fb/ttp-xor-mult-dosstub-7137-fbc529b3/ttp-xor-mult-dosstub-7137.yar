rule TTP_XOR_MULT_DOSStub_7137 {
  strings:
    $key_7137 = { 25 5f [2] 51 47 [2] 16 45 [2] 51 54 [2] 1f 58 [2] 13 52 [2] 04 59 [2] 1f 17 [2] 22 }

  condition:
    any of them
}