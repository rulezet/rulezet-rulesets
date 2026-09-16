rule TTP_XOR_MULT_DOSStub_152e {
  strings:
    $key_152e = { 41 46 [2] 35 5e [2] 72 5c [2] 35 4d [2] 7b 41 [2] 77 4b [2] 60 40 [2] 7b 0e [2] 46 }

  condition:
    any of them
}