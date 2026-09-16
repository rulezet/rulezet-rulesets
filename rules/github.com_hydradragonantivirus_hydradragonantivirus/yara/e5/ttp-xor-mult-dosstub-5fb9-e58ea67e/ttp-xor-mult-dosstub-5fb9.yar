rule TTP_XOR_MULT_DOSStub_5fb9 {
  strings:
    $key_5fb9 = { 0b d1 [2] 7f c9 [2] 38 cb [2] 7f da [2] 31 d6 [2] 3d dc [2] 2a d7 [2] 31 99 [2] 0c }

  condition:
    any of them
}