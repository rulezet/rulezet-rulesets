rule TTP_XOR_MULT_DOSStub_e00b {
  strings:
    $key_e00b = { b4 63 [2] c0 7b [2] 87 79 [2] c0 68 [2] 8e 64 [2] 82 6e [2] 95 65 [2] 8e 2b [2] b3 }

  condition:
    any of them
}