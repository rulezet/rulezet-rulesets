rule TTP_XOR_MULT_DOSStub_eea0 {
  strings:
    $key_eea0 = { ba c8 [2] ce d0 [2] 89 d2 [2] ce c3 [2] 80 cf [2] 8c c5 [2] 9b ce [2] 80 80 [2] bd }

  condition:
    any of them
}