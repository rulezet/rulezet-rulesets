rule TTP_XOR_MULT_DOSStub_2bb5 {
  strings:
    $key_2bb5 = { 7f dd [2] 0b c5 [2] 4c c7 [2] 0b d6 [2] 45 da [2] 49 d0 [2] 5e db [2] 45 95 [2] 78 }

  condition:
    any of them
}