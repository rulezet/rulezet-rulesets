rule TTP_XOR_MULT_DOSStub_c3e8 {
  strings:
    $key_c3e8 = { 97 80 [2] e3 98 [2] a4 9a [2] e3 8b [2] ad 87 [2] a1 8d [2] b6 86 [2] ad c8 [2] 90 }

  condition:
    any of them
}