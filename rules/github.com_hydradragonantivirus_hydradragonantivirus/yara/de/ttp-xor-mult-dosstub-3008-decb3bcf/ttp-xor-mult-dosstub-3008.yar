rule TTP_XOR_MULT_DOSStub_3008 {
  strings:
    $key_3008 = { 64 60 [2] 10 78 [2] 57 7a [2] 10 6b [2] 5e 67 [2] 52 6d [2] 45 66 [2] 5e 28 [2] 63 }

  condition:
    any of them
}