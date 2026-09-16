rule TTP_XOR_MULT_DOSStub_4eab {
  strings:
    $key_4eab = { 1a c3 [2] 6e db [2] 29 d9 [2] 6e c8 [2] 20 c4 [2] 2c ce [2] 3b c5 [2] 20 8b [2] 1d }

  condition:
    any of them
}