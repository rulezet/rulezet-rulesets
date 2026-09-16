rule TTP_XOR_MULT_DOSStub_245b {
  strings:
    $key_245b = { 70 33 [2] 04 2b [2] 43 29 [2] 04 38 [2] 4a 34 [2] 46 3e [2] 51 35 [2] 4a 7b [2] 77 }

  condition:
    any of them
}