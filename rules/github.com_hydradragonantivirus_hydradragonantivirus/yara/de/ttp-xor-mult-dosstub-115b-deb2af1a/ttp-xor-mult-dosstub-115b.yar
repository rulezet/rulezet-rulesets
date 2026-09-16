rule TTP_XOR_MULT_DOSStub_115b {
  strings:
    $key_115b = { 45 33 [2] 31 2b [2] 76 29 [2] 31 38 [2] 7f 34 [2] 73 3e [2] 64 35 [2] 7f 7b [2] 42 }

  condition:
    any of them
}