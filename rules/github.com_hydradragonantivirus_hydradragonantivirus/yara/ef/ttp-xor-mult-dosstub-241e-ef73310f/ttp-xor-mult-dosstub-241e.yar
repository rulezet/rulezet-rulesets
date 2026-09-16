rule TTP_XOR_MULT_DOSStub_241e {
  strings:
    $key_241e = { 70 76 [2] 04 6e [2] 43 6c [2] 04 7d [2] 4a 71 [2] 46 7b [2] 51 70 [2] 4a 3e [2] 77 }

  condition:
    any of them
}