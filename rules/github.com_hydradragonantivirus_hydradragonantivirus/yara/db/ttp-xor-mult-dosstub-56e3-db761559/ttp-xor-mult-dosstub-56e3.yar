rule TTP_XOR_MULT_DOSStub_56e3 {
  strings:
    $key_56e3 = { 02 8b [2] 76 93 [2] 31 91 [2] 76 80 [2] 38 8c [2] 34 86 [2] 23 8d [2] 38 c3 [2] 05 }

  condition:
    any of them
}