rule TTP_XOR_MULT_DOSStub_5a0e {
  strings:
    $key_5a0e = { 0e 66 [2] 7a 7e [2] 3d 7c [2] 7a 6d [2] 34 61 [2] 38 6b [2] 2f 60 [2] 34 2e [2] 09 }

  condition:
    any of them
}