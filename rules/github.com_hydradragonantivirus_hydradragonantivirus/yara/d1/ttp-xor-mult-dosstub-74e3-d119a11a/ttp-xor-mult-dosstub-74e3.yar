rule TTP_XOR_MULT_DOSStub_74e3 {
  strings:
    $key_74e3 = { 20 8b [2] 54 93 [2] 13 91 [2] 54 80 [2] 1a 8c [2] 16 86 [2] 01 8d [2] 1a c3 [2] 27 }

  condition:
    any of them
}