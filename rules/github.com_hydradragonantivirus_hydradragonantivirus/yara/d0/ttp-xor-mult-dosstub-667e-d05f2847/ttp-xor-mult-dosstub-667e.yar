rule TTP_XOR_MULT_DOSStub_667e {
  strings:
    $key_667e = { 32 16 [2] 46 0e [2] 01 0c [2] 46 1d [2] 08 11 [2] 04 1b [2] 13 10 [2] 08 5e [2] 35 }

  condition:
    any of them
}