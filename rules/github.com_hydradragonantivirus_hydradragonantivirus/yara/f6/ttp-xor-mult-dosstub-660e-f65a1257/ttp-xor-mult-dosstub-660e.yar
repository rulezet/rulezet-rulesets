rule TTP_XOR_MULT_DOSStub_660e {
  strings:
    $key_660e = { 32 66 [2] 46 7e [2] 01 7c [2] 46 6d [2] 08 61 [2] 04 6b [2] 13 60 [2] 08 2e [2] 35 }

  condition:
    any of them
}