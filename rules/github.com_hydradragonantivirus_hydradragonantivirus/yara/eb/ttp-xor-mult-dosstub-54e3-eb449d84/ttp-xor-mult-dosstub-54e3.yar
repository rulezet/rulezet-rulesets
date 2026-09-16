rule TTP_XOR_MULT_DOSStub_54e3 {
  strings:
    $key_54e3 = { 00 8b [2] 74 93 [2] 33 91 [2] 74 80 [2] 3a 8c [2] 36 86 [2] 21 8d [2] 3a c3 [2] 07 }

  condition:
    any of them
}