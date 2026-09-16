rule TTP_XOR_MULT_DOSStub_41e5 {
  strings:
    $key_41e5 = { 15 8d [2] 61 95 [2] 26 97 [2] 61 86 [2] 2f 8a [2] 23 80 [2] 34 8b [2] 2f c5 [2] 12 }

  condition:
    any of them
}