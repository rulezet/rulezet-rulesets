rule TTP_XOR_MULT_DOSStub_4eb9 {
  strings:
    $key_4eb9 = { 1a d1 [2] 6e c9 [2] 29 cb [2] 6e da [2] 20 d6 [2] 2c dc [2] 3b d7 [2] 20 99 [2] 1d }

  condition:
    any of them
}