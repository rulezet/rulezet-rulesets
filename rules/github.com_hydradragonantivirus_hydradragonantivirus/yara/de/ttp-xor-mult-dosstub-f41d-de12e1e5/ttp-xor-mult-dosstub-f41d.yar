rule TTP_XOR_MULT_DOSStub_f41d {
  strings:
    $key_f41d = { a0 75 [2] d4 6d [2] 93 6f [2] d4 7e [2] 9a 72 [2] 96 78 [2] 81 73 [2] 9a 3d [2] a7 }

  condition:
    any of them
}