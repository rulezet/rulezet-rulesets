rule TTP_XOR_MULT_DOSStub_3069 {
  strings:
    $key_3069 = { 64 01 [2] 10 19 [2] 57 1b [2] 10 0a [2] 5e 06 [2] 52 0c [2] 45 07 [2] 5e 49 [2] 63 }

  condition:
    any of them
}