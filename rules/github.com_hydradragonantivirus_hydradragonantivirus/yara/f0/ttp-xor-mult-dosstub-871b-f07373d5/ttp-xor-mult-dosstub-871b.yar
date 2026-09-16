rule TTP_XOR_MULT_DOSStub_871b {
  strings:
    $key_871b = { d3 73 [2] a7 6b [2] e0 69 [2] a7 78 [2] e9 74 [2] e5 7e [2] f2 75 [2] e9 3b [2] d4 }

  condition:
    any of them
}