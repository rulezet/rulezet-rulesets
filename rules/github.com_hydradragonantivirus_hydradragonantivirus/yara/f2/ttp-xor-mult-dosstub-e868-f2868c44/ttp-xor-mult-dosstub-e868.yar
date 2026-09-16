rule TTP_XOR_MULT_DOSStub_e868 {
  strings:
    $key_e868 = { bc 00 [2] c8 18 [2] 8f 1a [2] c8 0b [2] 86 07 [2] 8a 0d [2] 9d 06 [2] 86 48 [2] bb }

  condition:
    any of them
}