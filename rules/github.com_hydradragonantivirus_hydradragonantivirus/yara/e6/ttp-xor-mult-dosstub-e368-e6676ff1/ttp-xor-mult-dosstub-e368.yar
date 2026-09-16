rule TTP_XOR_MULT_DOSStub_e368 {
  strings:
    $key_e368 = { b7 00 [2] c3 18 [2] 84 1a [2] c3 0b [2] 8d 07 [2] 81 0d [2] 96 06 [2] 8d 48 [2] b0 }

  condition:
    any of them
}