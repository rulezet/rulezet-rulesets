rule TTP_XOR_MULT_DOSStub_240b {
  strings:
    $key_240b = { 70 63 [2] 04 7b [2] 43 79 [2] 04 68 [2] 4a 64 [2] 46 6e [2] 51 65 [2] 4a 2b [2] 77 }

  condition:
    any of them
}