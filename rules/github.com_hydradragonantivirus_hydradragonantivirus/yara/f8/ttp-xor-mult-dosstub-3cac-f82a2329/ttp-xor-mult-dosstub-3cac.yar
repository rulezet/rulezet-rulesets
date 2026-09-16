rule TTP_XOR_MULT_DOSStub_3cac {
  strings:
    $key_3cac = { 68 c4 [2] 1c dc [2] 5b de [2] 1c cf [2] 52 c3 [2] 5e c9 [2] 49 c2 [2] 52 8c [2] 6f }

  condition:
    any of them
}