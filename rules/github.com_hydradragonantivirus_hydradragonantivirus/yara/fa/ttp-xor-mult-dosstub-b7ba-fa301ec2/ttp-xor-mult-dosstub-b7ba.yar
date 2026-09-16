rule TTP_XOR_MULT_DOSStub_b7ba {
  strings:
    $key_b7ba = { e3 d2 [2] 97 ca [2] d0 c8 [2] 97 d9 [2] d9 d5 [2] d5 df [2] c2 d4 [2] d9 9a [2] e4 }

  condition:
    any of them
}