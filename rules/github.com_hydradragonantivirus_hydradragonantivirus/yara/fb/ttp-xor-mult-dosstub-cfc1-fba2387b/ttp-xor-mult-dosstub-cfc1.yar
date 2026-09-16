rule TTP_XOR_MULT_DOSStub_cfc1 {
  strings:
    $key_cfc1 = { 9b a9 [2] ef b1 [2] a8 b3 [2] ef a2 [2] a1 ae [2] ad a4 [2] ba af [2] a1 e1 [2] 9c }

  condition:
    any of them
}