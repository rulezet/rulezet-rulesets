rule TTP_XOR_MULT_DOSStub_e838 {
  strings:
    $key_e838 = { bc 50 [2] c8 48 [2] 8f 4a [2] c8 5b [2] 86 57 [2] 8a 5d [2] 9d 56 [2] 86 18 [2] bb }

  condition:
    any of them
}