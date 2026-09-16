rule TTP_XOR_MULT_DOSStub_114e {
  strings:
    $key_114e = { 45 26 [2] 31 3e [2] 76 3c [2] 31 2d [2] 7f 21 [2] 73 2b [2] 64 20 [2] 7f 6e [2] 42 }

  condition:
    any of them
}