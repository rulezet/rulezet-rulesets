rule TTP_XOR_MULT_DOSStub_667b {
  strings:
    $key_667b = { 32 13 [2] 46 0b [2] 01 09 [2] 46 18 [2] 08 14 [2] 04 1e [2] 13 15 [2] 08 5b [2] 35 }

  condition:
    any of them
}