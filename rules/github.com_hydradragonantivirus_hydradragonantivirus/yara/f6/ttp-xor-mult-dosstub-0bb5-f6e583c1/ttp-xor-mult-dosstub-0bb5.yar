rule TTP_XOR_MULT_DOSStub_0bb5 {
  strings:
    $key_0bb5 = { 5f dd [2] 2b c5 [2] 6c c7 [2] 2b d6 [2] 65 da [2] 69 d0 [2] 7e db [2] 65 95 [2] 58 }

  condition:
    any of them
}