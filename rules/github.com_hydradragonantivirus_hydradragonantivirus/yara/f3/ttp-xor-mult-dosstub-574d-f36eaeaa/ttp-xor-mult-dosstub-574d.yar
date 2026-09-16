rule TTP_XOR_MULT_DOSStub_574d {
  strings:
    $key_574d = { 03 25 [2] 77 3d [2] 30 3f [2] 77 2e [2] 39 22 [2] 35 28 [2] 22 23 [2] 39 6d [2] 04 }

  condition:
    any of them
}