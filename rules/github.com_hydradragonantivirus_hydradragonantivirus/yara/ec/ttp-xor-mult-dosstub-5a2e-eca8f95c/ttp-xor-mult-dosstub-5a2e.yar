rule TTP_XOR_MULT_DOSStub_5a2e {
  strings:
    $key_5a2e = { 0e 46 [2] 7a 5e [2] 3d 5c [2] 7a 4d [2] 34 41 [2] 38 4b [2] 2f 40 [2] 34 0e [2] 09 }

  condition:
    any of them
}