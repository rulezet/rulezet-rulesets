rule TTP_XOR_MULT_DOSStub_4ebd {
  strings:
    $key_4ebd = { 1a d5 [2] 6e cd [2] 29 cf [2] 6e de [2] 20 d2 [2] 2c d8 [2] 3b d3 [2] 20 9d [2] 1d }

  condition:
    any of them
}