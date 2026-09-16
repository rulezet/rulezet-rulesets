rule TTP_XOR_MULT_DOSStub_2fb9 {
  strings:
    $key_2fb9 = { 7b d1 [2] 0f c9 [2] 48 cb [2] 0f da [2] 41 d6 [2] 4d dc [2] 5a d7 [2] 41 99 [2] 7c }

  condition:
    any of them
}