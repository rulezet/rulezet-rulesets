rule TTP_XOR_MULT_DOSStub_3748 {
  strings:
    $key_3748 = { 63 20 [2] 17 38 [2] 50 3a [2] 17 2b [2] 59 27 [2] 55 2d [2] 42 26 [2] 59 68 [2] 64 }

  condition:
    any of them
}