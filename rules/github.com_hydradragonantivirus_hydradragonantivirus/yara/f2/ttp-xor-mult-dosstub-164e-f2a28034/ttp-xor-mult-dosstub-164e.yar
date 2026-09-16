rule TTP_XOR_MULT_DOSStub_164e {
  strings:
    $key_164e = { 42 26 [2] 36 3e [2] 71 3c [2] 36 2d [2] 78 21 [2] 74 2b [2] 63 20 [2] 78 6e [2] 45 }

  condition:
    any of them
}