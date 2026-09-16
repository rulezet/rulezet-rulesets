rule TTP_XOR_MULT_DOSStub_874c {
  strings:
    $key_874c = { d3 24 [2] a7 3c [2] e0 3e [2] a7 2f [2] e9 23 [2] e5 29 [2] f2 22 [2] e9 6c [2] d4 }

  condition:
    any of them
}