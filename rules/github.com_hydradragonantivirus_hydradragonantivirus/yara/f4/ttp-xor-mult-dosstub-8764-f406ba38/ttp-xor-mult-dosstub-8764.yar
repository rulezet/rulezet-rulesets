rule TTP_XOR_MULT_DOSStub_8764 {
  strings:
    $key_8764 = { d3 0c [2] a7 14 [2] e0 16 [2] a7 07 [2] e9 0b [2] e5 01 [2] f2 0a [2] e9 44 [2] d4 }

  condition:
    any of them
}