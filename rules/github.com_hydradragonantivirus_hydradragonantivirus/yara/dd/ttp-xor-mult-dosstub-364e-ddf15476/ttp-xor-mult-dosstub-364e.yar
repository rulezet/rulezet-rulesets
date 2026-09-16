rule TTP_XOR_MULT_DOSStub_364e {
  strings:
    $key_364e = { 62 26 [2] 16 3e [2] 51 3c [2] 16 2d [2] 58 21 [2] 54 2b [2] 43 20 [2] 58 6e [2] 65 }

  condition:
    any of them
}