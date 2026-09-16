rule TTP_XOR_MULT_DOSStub_514e {
  strings:
    $key_514e = { 05 26 [2] 71 3e [2] 36 3c [2] 71 2d [2] 3f 21 [2] 33 2b [2] 24 20 [2] 3f 6e [2] 02 }

  condition:
    any of them
}