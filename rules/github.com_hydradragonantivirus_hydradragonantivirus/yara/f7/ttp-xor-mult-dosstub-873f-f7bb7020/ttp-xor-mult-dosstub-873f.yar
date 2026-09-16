rule TTP_XOR_MULT_DOSStub_873f {
  strings:
    $key_873f = { d3 57 [2] a7 4f [2] e0 4d [2] a7 5c [2] e9 50 [2] e5 5a [2] f2 51 [2] e9 1f [2] d4 }

  condition:
    any of them
}