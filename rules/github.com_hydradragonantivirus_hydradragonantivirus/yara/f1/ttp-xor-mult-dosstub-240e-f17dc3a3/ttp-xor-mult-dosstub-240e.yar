rule TTP_XOR_MULT_DOSStub_240e {
  strings:
    $key_240e = { 70 66 [2] 04 7e [2] 43 7c [2] 04 6d [2] 4a 61 [2] 46 6b [2] 51 60 [2] 4a 2e [2] 77 }

  condition:
    any of them
}