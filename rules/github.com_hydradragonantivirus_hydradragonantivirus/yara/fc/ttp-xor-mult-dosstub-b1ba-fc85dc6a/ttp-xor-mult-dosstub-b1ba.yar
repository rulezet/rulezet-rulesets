rule TTP_XOR_MULT_DOSStub_b1ba {
  strings:
    $key_b1ba = { e5 d2 [2] 91 ca [2] d6 c8 [2] 91 d9 [2] df d5 [2] d3 df [2] c4 d4 [2] df 9a [2] e2 }

  condition:
    any of them
}