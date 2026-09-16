rule TTP_XOR_MULT_DOSStub_873e {
  strings:
    $key_873e = { d3 56 [2] a7 4e [2] e0 4c [2] a7 5d [2] e9 51 [2] e5 5b [2] f2 50 [2] e9 1e [2] d4 }

  condition:
    any of them
}