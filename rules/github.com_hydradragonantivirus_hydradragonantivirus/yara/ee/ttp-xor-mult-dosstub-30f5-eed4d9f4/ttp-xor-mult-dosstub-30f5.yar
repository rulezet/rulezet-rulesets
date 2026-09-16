rule TTP_XOR_MULT_DOSStub_30f5 {
  strings:
    $key_30f5 = { 64 9d [2] 10 85 [2] 57 87 [2] 10 96 [2] 5e 9a [2] 52 90 [2] 45 9b [2] 5e d5 [2] 63 }

  condition:
    any of them
}