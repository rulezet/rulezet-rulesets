rule TTP_XOR_MULT_DOSStub_e367 {
  strings:
    $key_e367 = { b7 0f [2] c3 17 [2] 84 15 [2] c3 04 [2] 8d 08 [2] 81 02 [2] 96 09 [2] 8d 47 [2] b0 }

  condition:
    any of them
}