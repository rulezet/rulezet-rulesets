rule TTP_XOR_MULT_DOSStub_e05b {
  strings:
    $key_e05b = { b4 33 [2] c0 2b [2] 87 29 [2] c0 38 [2] 8e 34 [2] 82 3e [2] 95 35 [2] 8e 7b [2] b3 }

  condition:
    any of them
}