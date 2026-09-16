rule TTP_XOR_MULT_DOSStub_e4ba {
  strings:
    $key_e4ba = { b0 d2 [2] c4 ca [2] 83 c8 [2] c4 d9 [2] 8a d5 [2] 86 df [2] 91 d4 [2] 8a 9a [2] b7 }

  condition:
    any of them
}