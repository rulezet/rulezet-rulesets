rule TTP_XOR_MULT_DOSStub_e03e {
  strings:
    $key_e03e = { b4 56 [2] c0 4e [2] 87 4c [2] c0 5d [2] 8e 51 [2] 82 5b [2] 95 50 [2] 8e 1e [2] b3 }

  condition:
    any of them
}