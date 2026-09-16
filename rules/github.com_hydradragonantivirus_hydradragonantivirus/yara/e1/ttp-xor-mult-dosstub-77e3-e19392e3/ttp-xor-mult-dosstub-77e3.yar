rule TTP_XOR_MULT_DOSStub_77e3 {
  strings:
    $key_77e3 = { 23 8b [2] 57 93 [2] 10 91 [2] 57 80 [2] 19 8c [2] 15 86 [2] 02 8d [2] 19 c3 [2] 24 }

  condition:
    any of them
}