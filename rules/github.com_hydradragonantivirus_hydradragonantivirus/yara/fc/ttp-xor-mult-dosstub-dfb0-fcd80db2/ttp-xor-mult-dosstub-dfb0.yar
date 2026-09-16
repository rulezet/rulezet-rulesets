rule TTP_XOR_MULT_DOSStub_dfb0 {
  strings:
    $key_dfb0 = { 8b d8 [2] ff c0 [2] b8 c2 [2] ff d3 [2] b1 df [2] bd d5 [2] aa de [2] b1 90 [2] 8c }

  condition:
    any of them
}