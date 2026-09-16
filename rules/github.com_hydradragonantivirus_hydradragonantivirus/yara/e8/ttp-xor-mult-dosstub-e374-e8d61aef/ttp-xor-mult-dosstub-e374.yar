rule TTP_XOR_MULT_DOSStub_e374 {
  strings:
    $key_e374 = { b7 1c [2] c3 04 [2] 84 06 [2] c3 17 [2] 8d 1b [2] 81 11 [2] 96 1a [2] 8d 54 [2] b0 }

  condition:
    any of them
}