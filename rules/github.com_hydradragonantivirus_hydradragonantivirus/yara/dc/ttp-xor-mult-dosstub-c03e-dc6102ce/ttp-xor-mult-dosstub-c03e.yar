rule TTP_XOR_MULT_DOSStub_c03e {
  strings:
    $key_c03e = { 94 56 [2] e0 4e [2] a7 4c [2] e0 5d [2] ae 51 [2] a2 5b [2] b5 50 [2] ae 1e [2] 93 }

  condition:
    any of them
}