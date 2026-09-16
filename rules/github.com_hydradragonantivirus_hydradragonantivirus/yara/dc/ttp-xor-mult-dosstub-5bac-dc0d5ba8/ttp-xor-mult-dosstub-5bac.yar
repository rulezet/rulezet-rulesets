rule TTP_XOR_MULT_DOSStub_5bac {
  strings:
    $key_5bac = { 0f c4 [2] 7b dc [2] 3c de [2] 7b cf [2] 35 c3 [2] 39 c9 [2] 2e c2 [2] 35 8c [2] 08 }

  condition:
    any of them
}