rule TTP_XOR_MULT_DOSStub_337b {
  strings:
    $key_337b = { 67 13 [2] 13 0b [2] 54 09 [2] 13 18 [2] 5d 14 [2] 51 1e [2] 46 15 [2] 5d 5b [2] 60 }

  condition:
    any of them
}