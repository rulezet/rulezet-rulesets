rule TTP_XOR_MULT_DOSStub_872d {
  strings:
    $key_872d = { d3 45 [2] a7 5d [2] e0 5f [2] a7 4e [2] e9 42 [2] e5 48 [2] f2 43 [2] e9 0d [2] d4 }

  condition:
    any of them
}