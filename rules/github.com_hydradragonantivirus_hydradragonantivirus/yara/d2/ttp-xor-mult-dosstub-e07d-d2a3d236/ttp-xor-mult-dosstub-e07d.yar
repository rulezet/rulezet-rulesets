rule TTP_XOR_MULT_DOSStub_e07d {
  strings:
    $key_e07d = { b4 15 [2] c0 0d [2] 87 0f [2] c0 1e [2] 8e 12 [2] 82 18 [2] 95 13 [2] 8e 5d [2] b3 }

  condition:
    any of them
}