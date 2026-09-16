rule TTP_XOR_MULT_DOSStub_e8a3 {
  strings:
    $key_e8a3 = { bc cb [2] c8 d3 [2] 8f d1 [2] c8 c0 [2] 86 cc [2] 8a c6 [2] 9d cd [2] 86 83 [2] bb }

  condition:
    any of them
}