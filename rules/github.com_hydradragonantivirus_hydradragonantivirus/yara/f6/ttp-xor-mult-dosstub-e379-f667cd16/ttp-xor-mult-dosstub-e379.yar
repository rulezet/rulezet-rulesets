rule TTP_XOR_MULT_DOSStub_e379 {
  strings:
    $key_e379 = { b7 11 [2] c3 09 [2] 84 0b [2] c3 1a [2] 8d 16 [2] 81 1c [2] 96 17 [2] 8d 59 [2] b0 }

  condition:
    any of them
}