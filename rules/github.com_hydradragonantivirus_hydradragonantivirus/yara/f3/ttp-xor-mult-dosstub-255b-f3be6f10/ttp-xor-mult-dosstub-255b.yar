rule TTP_XOR_MULT_DOSStub_255b {
  strings:
    $key_255b = { 71 33 [2] 05 2b [2] 42 29 [2] 05 38 [2] 4b 34 [2] 47 3e [2] 50 35 [2] 4b 7b [2] 76 }

  condition:
    any of them
}