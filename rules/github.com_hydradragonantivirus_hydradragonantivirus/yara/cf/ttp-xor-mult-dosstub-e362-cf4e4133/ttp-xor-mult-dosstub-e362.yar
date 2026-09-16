rule TTP_XOR_MULT_DOSStub_e362 {
  strings:
    $key_e362 = { b7 0a [2] c3 12 [2] 84 10 [2] c3 01 [2] 8d 0d [2] 81 07 [2] 96 0c [2] 8d 42 [2] b0 }

  condition:
    any of them
}