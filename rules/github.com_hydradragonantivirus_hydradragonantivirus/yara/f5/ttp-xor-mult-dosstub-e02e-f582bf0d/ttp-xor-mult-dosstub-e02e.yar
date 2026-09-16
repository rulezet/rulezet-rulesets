rule TTP_XOR_MULT_DOSStub_e02e {
  strings:
    $key_e02e = { b4 46 [2] c0 5e [2] 87 5c [2] c0 4d [2] 8e 41 [2] 82 4b [2] 95 40 [2] 8e 0e [2] b3 }

  condition:
    any of them
}