rule TTP_XOR_MULT_DOSStub_3144 {
  strings:
    $key_3144 = { 65 2c [2] 11 34 [2] 56 36 [2] 11 27 [2] 5f 2b [2] 53 21 [2] 44 2a [2] 5f 64 [2] 62 }

  condition:
    any of them
}