rule TTP_XOR_MULT_DOSStub_3762 {
  strings:
    $key_3762 = { 63 0a [2] 17 12 [2] 50 10 [2] 17 01 [2] 59 0d [2] 55 07 [2] 42 0c [2] 59 42 [2] 64 }

  condition:
    any of them
}