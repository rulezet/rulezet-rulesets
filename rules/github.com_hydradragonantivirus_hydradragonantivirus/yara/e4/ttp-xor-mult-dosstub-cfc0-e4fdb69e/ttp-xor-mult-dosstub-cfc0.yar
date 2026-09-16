rule TTP_XOR_MULT_DOSStub_cfc0 {
  strings:
    $key_cfc0 = { 9b a8 [2] ef b0 [2] a8 b2 [2] ef a3 [2] a1 af [2] ad a5 [2] ba ae [2] a1 e0 [2] 9c }

  condition:
    any of them
}