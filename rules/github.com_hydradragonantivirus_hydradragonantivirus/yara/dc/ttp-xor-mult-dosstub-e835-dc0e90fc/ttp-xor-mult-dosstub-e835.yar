rule TTP_XOR_MULT_DOSStub_e835 {
  strings:
    $key_e835 = { bc 5d [2] c8 45 [2] 8f 47 [2] c8 56 [2] 86 5a [2] 8a 50 [2] 9d 5b [2] 86 15 [2] bb }

  condition:
    any of them
}