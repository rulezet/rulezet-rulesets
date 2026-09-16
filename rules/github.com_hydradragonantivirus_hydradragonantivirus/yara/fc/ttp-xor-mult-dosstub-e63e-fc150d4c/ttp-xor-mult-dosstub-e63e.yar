rule TTP_XOR_MULT_DOSStub_e63e {
  strings:
    $key_e63e = { b2 56 [2] c6 4e [2] 81 4c [2] c6 5d [2] 88 51 [2] 84 5b [2] 93 50 [2] 88 1e [2] b5 }

  condition:
    any of them
}