rule TTP_XOR_MULT_DOSStub_0eab {
  strings:
    $key_0eab = { 5a c3 [2] 2e db [2] 69 d9 [2] 2e c8 [2] 60 c4 [2] 6c ce [2] 7b c5 [2] 60 8b [2] 5d }

  condition:
    any of them
}