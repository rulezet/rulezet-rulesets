rule TTP_XOR_MULT_DOSStub_e851 {
  strings:
    $key_e851 = { bc 39 [2] c8 21 [2] 8f 23 [2] c8 32 [2] 86 3e [2] 8a 34 [2] 9d 3f [2] 86 71 [2] bb }

  condition:
    any of them
}