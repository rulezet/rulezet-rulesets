rule TTP_XOR_MULT_DOSStub_e466 {
  strings:
    $key_e466 = { b0 0e [2] c4 16 [2] 83 14 [2] c4 05 [2] 8a 09 [2] 86 03 [2] 91 08 [2] 8a 46 [2] b7 }

  condition:
    any of them
}