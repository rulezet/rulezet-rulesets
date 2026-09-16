rule TTP_XOR_MULT_DOSStub_6c37 {
  strings:
    $key_6c37 = { 38 5f [2] 4c 47 [2] 0b 45 [2] 4c 54 [2] 02 58 [2] 0e 52 [2] 19 59 [2] 02 17 [2] 3f }

  condition:
    any of them
}