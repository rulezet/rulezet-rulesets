rule TTP_XOR_MULT_DOSStub_71b1 {
  strings:
    $key_71b1 = { 25 d9 [2] 51 c1 [2] 16 c3 [2] 51 d2 [2] 1f de [2] 13 d4 [2] 04 df [2] 1f 91 [2] 22 }

  condition:
    any of them
}