rule TTP_XOR_MULT_DOSStub_e332 {
  strings:
    $key_e332 = { b7 5a [2] c3 42 [2] 84 40 [2] c3 51 [2] 8d 5d [2] 81 57 [2] 96 5c [2] 8d 12 [2] b0 }

  condition:
    any of them
}