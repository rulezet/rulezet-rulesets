rule TTP_XOR_MULT_DOSStub_7bb2 {
  strings:
    $key_7bb2 = { 2f da [2] 5b c2 [2] 1c c0 [2] 5b d1 [2] 15 dd [2] 19 d7 [2] 0e dc [2] 15 92 [2] 28 }

  condition:
    any of them
}