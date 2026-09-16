rule TTP_XOR_MULT_DOSStub_6215 {
  strings:
    $key_6215 = { 36 7d [2] 42 65 [2] 05 67 [2] 42 76 [2] 0c 7a [2] 00 70 [2] 17 7b [2] 0c 35 [2] 31 }

  condition:
    any of them
}