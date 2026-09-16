rule TTP_XOR_MULT_DOSStub_c72e {
  strings:
    $key_c72e = { 93 46 [2] e7 5e [2] a0 5c [2] e7 4d [2] a9 41 [2] a5 4b [2] b2 40 [2] a9 0e [2] 94 }

  condition:
    any of them
}