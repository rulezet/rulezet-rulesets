rule TTP_XOR_MULT_DOSStub_4eb8 {
  strings:
    $key_4eb8 = { 1a d0 [2] 6e c8 [2] 29 ca [2] 6e db [2] 20 d7 [2] 2c dd [2] 3b d6 [2] 20 98 [2] 1d }

  condition:
    any of them
}