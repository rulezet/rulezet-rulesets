rule TTP_XOR_MULT_DOSStub_5a3e {
  strings:
    $key_5a3e = { 0e 56 [2] 7a 4e [2] 3d 4c [2] 7a 5d [2] 34 51 [2] 38 5b [2] 2f 50 [2] 34 1e [2] 09 }

  condition:
    any of them
}