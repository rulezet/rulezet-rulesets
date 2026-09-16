rule TTP_XOR_MULT_DOSStub_11e5 {
  strings:
    $key_11e5 = { 45 8d [2] 31 95 [2] 76 97 [2] 31 86 [2] 7f 8a [2] 73 80 [2] 64 8b [2] 7f c5 [2] 42 }

  condition:
    any of them
}