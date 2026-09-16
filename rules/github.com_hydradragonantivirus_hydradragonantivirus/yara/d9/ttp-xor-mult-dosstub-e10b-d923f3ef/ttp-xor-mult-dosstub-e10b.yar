rule TTP_XOR_MULT_DOSStub_e10b {
  strings:
    $key_e10b = { b5 63 [2] c1 7b [2] 86 79 [2] c1 68 [2] 8f 64 [2] 83 6e [2] 94 65 [2] 8f 2b [2] b2 }

  condition:
    any of them
}