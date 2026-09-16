rule TTP_XOR_MULT_DOSStub_e00e {
  strings:
    $key_e00e = { b4 66 [2] c0 7e [2] 87 7c [2] c0 6d [2] 8e 61 [2] 82 6b [2] 95 60 [2] 8e 2e [2] b3 }

  condition:
    any of them
}