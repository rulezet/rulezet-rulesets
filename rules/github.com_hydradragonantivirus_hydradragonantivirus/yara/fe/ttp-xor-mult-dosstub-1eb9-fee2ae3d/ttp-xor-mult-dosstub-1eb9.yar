rule TTP_XOR_MULT_DOSStub_1eb9 {
  strings:
    $key_1eb9 = { 4a d1 [2] 3e c9 [2] 79 cb [2] 3e da [2] 70 d6 [2] 7c dc [2] 6b d7 [2] 70 99 [2] 4d }

  condition:
    any of them
}