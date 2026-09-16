rule TTP_XOR_MULT_DOSStub_e841 {
  strings:
    $key_e841 = { bc 29 [2] c8 31 [2] 8f 33 [2] c8 22 [2] 86 2e [2] 8a 24 [2] 9d 2f [2] 86 61 [2] bb }

  condition:
    any of them
}