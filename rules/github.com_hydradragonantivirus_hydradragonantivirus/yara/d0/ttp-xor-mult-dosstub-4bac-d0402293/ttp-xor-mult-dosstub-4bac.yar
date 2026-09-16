rule TTP_XOR_MULT_DOSStub_4bac {
  strings:
    $key_4bac = { 1f c4 [2] 6b dc [2] 2c de [2] 6b cf [2] 25 c3 [2] 29 c9 [2] 3e c2 [2] 25 8c [2] 18 }

  condition:
    any of them
}