rule TTP_XOR_MULT_DOSStub_152b {
  strings:
    $key_152b = { 41 43 [2] 35 5b [2] 72 59 [2] 35 48 [2] 7b 44 [2] 77 4e [2] 60 45 [2] 7b 0b [2] 46 }

  condition:
    any of them
}