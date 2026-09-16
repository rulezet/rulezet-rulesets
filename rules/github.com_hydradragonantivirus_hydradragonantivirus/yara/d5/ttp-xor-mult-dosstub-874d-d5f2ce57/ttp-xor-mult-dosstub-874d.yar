rule TTP_XOR_MULT_DOSStub_874d {
  strings:
    $key_874d = { d3 25 [2] a7 3d [2] e0 3f [2] a7 2e [2] e9 22 [2] e5 28 [2] f2 23 [2] e9 6d [2] d4 }

  condition:
    any of them
}