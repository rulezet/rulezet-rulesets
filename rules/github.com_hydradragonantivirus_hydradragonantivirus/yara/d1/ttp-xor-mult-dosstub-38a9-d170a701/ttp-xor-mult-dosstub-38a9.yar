rule TTP_XOR_MULT_DOSStub_38a9 {
  strings:
    $key_38a9 = { 6c c1 [2] 18 d9 [2] 5f db [2] 18 ca [2] 56 c6 [2] 5a cc [2] 4d c7 [2] 56 89 [2] 6b }

  condition:
    any of them
}