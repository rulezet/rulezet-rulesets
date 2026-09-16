rule TTP_XOR_MULT_DOSStub_e82b {
  strings:
    $key_e82b = { bc 43 [2] c8 5b [2] 8f 59 [2] c8 48 [2] 86 44 [2] 8a 4e [2] 9d 45 [2] 86 0b [2] bb }

  condition:
    any of them
}