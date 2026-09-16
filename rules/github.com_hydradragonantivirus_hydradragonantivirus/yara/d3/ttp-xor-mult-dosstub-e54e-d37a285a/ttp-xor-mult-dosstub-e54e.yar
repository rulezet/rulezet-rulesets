rule TTP_XOR_MULT_DOSStub_e54e {
  strings:
    $key_e54e = { b1 26 [2] c5 3e [2] 82 3c [2] c5 2d [2] 8b 21 [2] 87 2b [2] 90 20 [2] 8b 6e [2] b6 }

  condition:
    any of them
}