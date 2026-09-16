rule TTP_XOR_MULT_DOSStub_871d {
  strings:
    $key_871d = { d3 75 [2] a7 6d [2] e0 6f [2] a7 7e [2] e9 72 [2] e5 78 [2] f2 73 [2] e9 3d [2] d4 }

  condition:
    any of them
}