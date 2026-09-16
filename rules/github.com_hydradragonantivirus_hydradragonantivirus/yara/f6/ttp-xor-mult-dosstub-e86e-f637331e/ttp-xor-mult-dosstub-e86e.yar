rule TTP_XOR_MULT_DOSStub_e86e {
  strings:
    $key_e86e = { bc 06 [2] c8 1e [2] 8f 1c [2] c8 0d [2] 86 01 [2] 8a 0b [2] 9d 00 [2] 86 4e [2] bb }

  condition:
    any of them
}