rule TTP_XOR_MULT_DOSStub_24d2 {
  strings:
    $key_24d2 = { 70 ba [2] 04 a2 [2] 43 a0 [2] 04 b1 [2] 4a bd [2] 46 b7 [2] 51 bc [2] 4a f2 [2] 77 }

  condition:
    any of them
}