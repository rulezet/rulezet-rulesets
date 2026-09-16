rule TTP_XOR_MULT_DOSStub_e168 {
  strings:
    $key_e168 = { b5 00 [2] c1 18 [2] 86 1a [2] c1 0b [2] 8f 07 [2] 83 0d [2] 94 06 [2] 8f 48 [2] b2 }

  condition:
    any of them
}