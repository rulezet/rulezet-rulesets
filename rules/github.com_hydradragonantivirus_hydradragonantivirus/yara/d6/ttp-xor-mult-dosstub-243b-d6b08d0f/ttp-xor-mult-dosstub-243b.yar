rule TTP_XOR_MULT_DOSStub_243b {
  strings:
    $key_243b = { 70 53 [2] 04 4b [2] 43 49 [2] 04 58 [2] 4a 54 [2] 46 5e [2] 51 55 [2] 4a 1b [2] 77 }

  condition:
    any of them
}