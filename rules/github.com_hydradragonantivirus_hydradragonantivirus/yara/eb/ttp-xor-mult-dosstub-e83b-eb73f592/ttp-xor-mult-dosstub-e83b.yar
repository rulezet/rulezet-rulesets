rule TTP_XOR_MULT_DOSStub_e83b {
  strings:
    $key_e83b = { bc 53 [2] c8 4b [2] 8f 49 [2] c8 58 [2] 86 54 [2] 8a 5e [2] 9d 55 [2] 86 1b [2] bb }

  condition:
    any of them
}