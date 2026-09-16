rule TTP_XOR_MULT_DOSStub_213e {
  strings:
    $key_213e = { 75 56 [2] 01 4e [2] 46 4c [2] 01 5d [2] 4f 51 [2] 43 5b [2] 54 50 [2] 4f 1e [2] 72 }

  condition:
    any of them
}