rule TTP_XOR_MULT_DOSStub_e831 {
  strings:
    $key_e831 = { bc 59 [2] c8 41 [2] 8f 43 [2] c8 52 [2] 86 5e [2] 8a 54 [2] 9d 5f [2] 86 11 [2] bb }

  condition:
    any of them
}