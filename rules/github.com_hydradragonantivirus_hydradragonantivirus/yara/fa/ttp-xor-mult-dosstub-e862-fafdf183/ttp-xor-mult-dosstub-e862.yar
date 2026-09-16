rule TTP_XOR_MULT_DOSStub_e862 {
  strings:
    $key_e862 = { bc 0a [2] c8 12 [2] 8f 10 [2] c8 01 [2] 86 0d [2] 8a 07 [2] 9d 0c [2] 86 42 [2] bb }

  condition:
    any of them
}