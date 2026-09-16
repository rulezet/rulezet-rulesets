rule TTP_XOR_MULT_DOSStub_e54d {
  strings:
    $key_e54d = { b1 25 [2] c5 3d [2] 82 3f [2] c5 2e [2] 8b 22 [2] 87 28 [2] 90 23 [2] 8b 6d [2] b6 }

  condition:
    any of them
}