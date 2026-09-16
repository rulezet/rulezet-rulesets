rule TTP_XOR_MULT_DOSStub_100b {
  strings:
    $key_100b = { 44 63 [2] 30 7b [2] 77 79 [2] 30 68 [2] 7e 64 [2] 72 6e [2] 65 65 [2] 7e 2b [2] 43 }

  condition:
    any of them
}