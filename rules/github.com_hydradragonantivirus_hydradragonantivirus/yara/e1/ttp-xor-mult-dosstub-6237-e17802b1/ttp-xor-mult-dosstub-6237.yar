rule TTP_XOR_MULT_DOSStub_6237 {
  strings:
    $key_6237 = { 36 5f [2] 42 47 [2] 05 45 [2] 42 54 [2] 0c 58 [2] 00 52 [2] 17 59 [2] 0c 17 [2] 31 }

  condition:
    any of them
}