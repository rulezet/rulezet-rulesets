rule TTP_XOR_MULT_DOSStub_c8b2 {
  strings:
    $key_c8b2 = { 9c da [2] e8 c2 [2] af c0 [2] e8 d1 [2] a6 dd [2] aa d7 [2] bd dc [2] a6 92 [2] 9b }

  condition:
    any of them
}