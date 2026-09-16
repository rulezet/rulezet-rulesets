rule TTP_XOR_MULT_DOSStub_5137 {
  strings:
    $key_5137 = { 05 5f [2] 71 47 [2] 36 45 [2] 71 54 [2] 3f 58 [2] 33 52 [2] 24 59 [2] 3f 17 [2] 02 }

  condition:
    any of them
}