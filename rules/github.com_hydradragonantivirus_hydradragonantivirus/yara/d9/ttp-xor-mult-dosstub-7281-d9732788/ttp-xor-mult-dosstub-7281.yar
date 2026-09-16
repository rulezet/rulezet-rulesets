rule TTP_XOR_MULT_DOSStub_7281 {
  strings:
    $key_7281 = { 26 e9 [2] 52 f1 [2] 15 f3 [2] 52 e2 [2] 1c ee [2] 10 e4 [2] 07 ef [2] 1c a1 [2] 21 }

  condition:
    any of them
}