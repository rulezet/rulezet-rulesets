rule TTP_XOR_MULT_DOSStub_327e {
  strings:
    $key_327e = { 66 16 [2] 12 0e [2] 55 0c [2] 12 1d [2] 5c 11 [2] 50 1b [2] 47 10 [2] 5c 5e [2] 61 }

  condition:
    any of them
}