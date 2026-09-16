rule TTP_XOR_MULT_DOSStub_153b {
  strings:
    $key_153b = { 41 53 [2] 35 4b [2] 72 49 [2] 35 58 [2] 7b 54 [2] 77 5e [2] 60 55 [2] 7b 1b [2] 46 }

  condition:
    any of them
}