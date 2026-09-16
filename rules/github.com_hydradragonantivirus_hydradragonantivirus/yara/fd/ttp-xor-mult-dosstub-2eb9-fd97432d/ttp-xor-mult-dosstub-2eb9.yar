rule TTP_XOR_MULT_DOSStub_2eb9 {
  strings:
    $key_2eb9 = { 7a d1 [2] 0e c9 [2] 49 cb [2] 0e da [2] 40 d6 [2] 4c dc [2] 5b d7 [2] 40 99 [2] 7d }

  condition:
    any of them
}