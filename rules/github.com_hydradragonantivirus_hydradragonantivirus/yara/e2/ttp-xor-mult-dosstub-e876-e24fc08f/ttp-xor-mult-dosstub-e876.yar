rule TTP_XOR_MULT_DOSStub_e876 {
  strings:
    $key_e876 = { bc 1e [2] c8 06 [2] 8f 04 [2] c8 15 [2] 86 19 [2] 8a 13 [2] 9d 18 [2] 86 56 [2] bb }

  condition:
    any of them
}