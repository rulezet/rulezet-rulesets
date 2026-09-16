rule TTP_XOR_MULT_DOSStub_3eaa {
  strings:
    $key_3eaa = { 6a c2 [2] 1e da [2] 59 d8 [2] 1e c9 [2] 50 c5 [2] 5c cf [2] 4b c4 [2] 50 8a [2] 6d }

  condition:
    any of them
}