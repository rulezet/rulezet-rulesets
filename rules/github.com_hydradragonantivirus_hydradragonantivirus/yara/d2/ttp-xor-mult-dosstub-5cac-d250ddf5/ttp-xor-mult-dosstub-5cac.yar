rule TTP_XOR_MULT_DOSStub_5cac {
  strings:
    $key_5cac = { 08 c4 [2] 7c dc [2] 3b de [2] 7c cf [2] 32 c3 [2] 3e c9 [2] 29 c2 [2] 32 8c [2] 0f }

  condition:
    any of them
}