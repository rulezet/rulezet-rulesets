rule TTP_XOR_MULT_DOSStub_150b {
  strings:
    $key_150b = { 41 63 [2] 35 7b [2] 72 79 [2] 35 68 [2] 7b 64 [2] 77 6e [2] 60 65 [2] 7b 2b [2] 46 }

  condition:
    any of them
}