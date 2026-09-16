rule TTP_XOR_MULT_DOSStub_2fa7 {
  strings:
    $key_2fa7 = { 7b cf [2] 0f d7 [2] 48 d5 [2] 0f c4 [2] 41 c8 [2] 4d c2 [2] 5a c9 [2] 41 87 [2] 7c }

  condition:
    any of them
}