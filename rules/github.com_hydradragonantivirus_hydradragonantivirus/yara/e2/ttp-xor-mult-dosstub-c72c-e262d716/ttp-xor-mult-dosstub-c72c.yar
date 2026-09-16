rule TTP_XOR_MULT_DOSStub_c72c {
  strings:
    $key_c72c = { 93 44 [2] e7 5c [2] a0 5e [2] e7 4f [2] a9 43 [2] a5 49 [2] b2 42 [2] a9 0c [2] 94 }

  condition:
    any of them
}