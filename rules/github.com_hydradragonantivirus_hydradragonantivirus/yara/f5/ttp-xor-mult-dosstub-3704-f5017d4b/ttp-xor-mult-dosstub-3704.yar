rule TTP_XOR_MULT_DOSStub_3704 {
  strings:
    $key_3704 = { 63 6c [2] 17 74 [2] 50 76 [2] 17 67 [2] 59 6b [2] 55 61 [2] 42 6a [2] 59 24 [2] 64 }

  condition:
    any of them
}