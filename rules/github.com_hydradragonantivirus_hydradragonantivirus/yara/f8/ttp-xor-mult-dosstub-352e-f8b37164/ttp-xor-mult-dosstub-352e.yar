rule TTP_XOR_MULT_DOSStub_352e {
  strings:
    $key_352e = { 61 46 [2] 15 5e [2] 52 5c [2] 15 4d [2] 5b 41 [2] 57 4b [2] 40 40 [2] 5b 0e [2] 66 }

  condition:
    any of them
}