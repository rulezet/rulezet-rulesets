rule TTP_XOR_MULT_DOSStub_e860 {
  strings:
    $key_e860 = { bc 08 [2] c8 10 [2] 8f 12 [2] c8 03 [2] 86 0f [2] 8a 05 [2] 9d 0e [2] 86 40 [2] bb }

  condition:
    any of them
}