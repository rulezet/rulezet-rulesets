rule TTP_XOR_MULT_DOSStub_e85b {
  strings:
    $key_e85b = { bc 33 [2] c8 2b [2] 8f 29 [2] c8 38 [2] 86 34 [2] 8a 3e [2] 9d 35 [2] 86 7b [2] bb }

  condition:
    any of them
}