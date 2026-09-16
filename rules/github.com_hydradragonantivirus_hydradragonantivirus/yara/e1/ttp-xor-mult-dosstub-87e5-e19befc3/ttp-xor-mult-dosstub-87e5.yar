rule TTP_XOR_MULT_DOSStub_87e5 {
  strings:
    $key_87e5 = { d3 8d [2] a7 95 [2] e0 97 [2] a7 86 [2] e9 8a [2] e5 80 [2] f2 8b [2] e9 c5 [2] d4 }

  condition:
    any of them
}