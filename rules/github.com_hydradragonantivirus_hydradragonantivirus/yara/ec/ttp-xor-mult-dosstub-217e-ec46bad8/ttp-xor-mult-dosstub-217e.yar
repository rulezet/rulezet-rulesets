rule TTP_XOR_MULT_DOSStub_217e {
  strings:
    $key_217e = { 75 16 [2] 01 0e [2] 46 0c [2] 01 1d [2] 4f 11 [2] 43 1b [2] 54 10 [2] 4f 5e [2] 72 }

  condition:
    any of them
}