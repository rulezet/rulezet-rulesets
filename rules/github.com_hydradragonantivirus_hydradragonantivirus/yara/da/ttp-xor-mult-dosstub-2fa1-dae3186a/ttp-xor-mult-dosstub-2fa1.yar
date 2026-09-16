rule TTP_XOR_MULT_DOSStub_2fa1 {
  strings:
    $key_2fa1 = { 7b c9 [2] 0f d1 [2] 48 d3 [2] 0f c2 [2] 41 ce [2] 4d c4 [2] 5a cf [2] 41 81 [2] 7c }

  condition:
    any of them
}