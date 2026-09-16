rule TTP_XOR_MULT_DOSStub_cfd3 {
  strings:
    $key_cfd3 = { 9b bb [2] ef a3 [2] a8 a1 [2] ef b0 [2] a1 bc [2] ad b6 [2] ba bd [2] a1 f3 [2] 9c }

  condition:
    any of them
}