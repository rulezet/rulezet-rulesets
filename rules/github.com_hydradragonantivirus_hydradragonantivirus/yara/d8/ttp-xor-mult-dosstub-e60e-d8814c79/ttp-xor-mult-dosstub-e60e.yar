rule TTP_XOR_MULT_DOSStub_e60e {
  strings:
    $key_e60e = { b2 66 [2] c6 7e [2] 81 7c [2] c6 6d [2] 88 61 [2] 84 6b [2] 93 60 [2] 88 2e [2] b5 }

  condition:
    any of them
}