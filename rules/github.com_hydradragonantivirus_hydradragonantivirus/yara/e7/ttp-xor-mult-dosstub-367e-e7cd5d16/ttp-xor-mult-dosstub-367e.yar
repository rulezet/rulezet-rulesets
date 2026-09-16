rule TTP_XOR_MULT_DOSStub_367e {
  strings:
    $key_367e = { 62 16 [2] 16 0e [2] 51 0c [2] 16 1d [2] 58 11 [2] 54 1b [2] 43 10 [2] 58 5e [2] 65 }

  condition:
    any of them
}