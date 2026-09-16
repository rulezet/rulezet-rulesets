rule TTP_XOR_MULT_DOSStub_241d {
  strings:
    $key_241d = { 70 75 [2] 04 6d [2] 43 6f [2] 04 7e [2] 4a 72 [2] 46 78 [2] 51 73 [2] 4a 3d [2] 77 }

  condition:
    any of them
}