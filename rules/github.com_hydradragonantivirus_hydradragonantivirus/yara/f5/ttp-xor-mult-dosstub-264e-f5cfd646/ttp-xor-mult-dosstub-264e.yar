rule TTP_XOR_MULT_DOSStub_264e {
  strings:
    $key_264e = { 72 26 [2] 06 3e [2] 41 3c [2] 06 2d [2] 48 21 [2] 44 2b [2] 53 20 [2] 48 6e [2] 75 }

  condition:
    any of them
}