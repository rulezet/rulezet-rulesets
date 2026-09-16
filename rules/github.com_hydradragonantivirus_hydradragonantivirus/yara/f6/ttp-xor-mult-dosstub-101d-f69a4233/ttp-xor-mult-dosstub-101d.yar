rule TTP_XOR_MULT_DOSStub_101d {
  strings:
    $key_101d = { 44 75 [2] 30 6d [2] 77 6f [2] 30 7e [2] 7e 72 [2] 72 78 [2] 65 73 [2] 7e 3d [2] 43 }

  condition:
    any of them
}