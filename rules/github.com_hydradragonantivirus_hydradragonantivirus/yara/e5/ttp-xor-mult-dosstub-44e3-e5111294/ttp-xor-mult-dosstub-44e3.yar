rule TTP_XOR_MULT_DOSStub_44e3 {
  strings:
    $key_44e3 = { 10 8b [2] 64 93 [2] 23 91 [2] 64 80 [2] 2a 8c [2] 26 86 [2] 31 8d [2] 2a c3 [2] 17 }

  condition:
    any of them
}