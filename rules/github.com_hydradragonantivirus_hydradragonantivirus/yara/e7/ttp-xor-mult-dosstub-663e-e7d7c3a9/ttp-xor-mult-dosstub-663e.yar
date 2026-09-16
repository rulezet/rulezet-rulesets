rule TTP_XOR_MULT_DOSStub_663e {
  strings:
    $key_663e = { 32 56 [2] 46 4e [2] 01 4c [2] 46 5d [2] 08 51 [2] 04 5b [2] 13 50 [2] 08 1e [2] 35 }

  condition:
    any of them
}