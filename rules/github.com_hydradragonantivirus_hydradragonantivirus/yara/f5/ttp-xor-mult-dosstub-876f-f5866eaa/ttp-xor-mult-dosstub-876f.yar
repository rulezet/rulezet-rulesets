rule TTP_XOR_MULT_DOSStub_876f {
  strings:
    $key_876f = { d3 07 [2] a7 1f [2] e0 1d [2] a7 0c [2] e9 00 [2] e5 0a [2] f2 01 [2] e9 4f [2] d4 }

  condition:
    any of them
}