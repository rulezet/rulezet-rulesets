rule TTP_XOR_MULT_DOSStub_a61d {
  strings:
    $key_a61d = { f2 75 [2] 86 6d [2] c1 6f [2] 86 7e [2] c8 72 [2] c4 78 [2] d3 73 [2] c8 3d [2] f5 }

  condition:
    any of them
}