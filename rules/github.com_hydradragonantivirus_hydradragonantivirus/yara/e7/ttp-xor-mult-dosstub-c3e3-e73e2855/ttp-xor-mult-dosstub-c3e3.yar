rule TTP_XOR_MULT_DOSStub_c3e3 {
  strings:
    $key_c3e3 = { 97 8b [2] e3 93 [2] a4 91 [2] e3 80 [2] ad 8c [2] a1 86 [2] b6 8d [2] ad c3 [2] 90 }

  condition:
    any of them
}