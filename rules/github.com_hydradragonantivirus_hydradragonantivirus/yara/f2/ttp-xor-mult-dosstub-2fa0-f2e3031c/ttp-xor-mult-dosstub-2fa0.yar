rule TTP_XOR_MULT_DOSStub_2fa0 {
  strings:
    $key_2fa0 = { 7b c8 [2] 0f d0 [2] 48 d2 [2] 0f c3 [2] 41 cf [2] 4d c5 [2] 5a ce [2] 41 80 [2] 7c }

  condition:
    any of them
}