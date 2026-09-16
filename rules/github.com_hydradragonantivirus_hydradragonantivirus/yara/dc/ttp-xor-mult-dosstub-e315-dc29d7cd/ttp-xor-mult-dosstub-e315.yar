rule TTP_XOR_MULT_DOSStub_e315 {
  strings:
    $key_e315 = { b7 7d [2] c3 65 [2] 84 67 [2] c3 76 [2] 8d 7a [2] 81 70 [2] 96 7b [2] 8d 35 [2] b0 }

  condition:
    any of them
}