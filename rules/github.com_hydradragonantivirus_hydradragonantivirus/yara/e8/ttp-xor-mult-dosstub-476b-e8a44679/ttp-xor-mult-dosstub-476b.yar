rule TTP_XOR_MULT_DOSStub_476b {
  strings:
    $key_476b = { 13 03 [2] 67 1b [2] 20 19 [2] 67 08 [2] 29 04 [2] 25 0e [2] 32 05 [2] 29 4b [2] 14 }

  condition:
    any of them
}