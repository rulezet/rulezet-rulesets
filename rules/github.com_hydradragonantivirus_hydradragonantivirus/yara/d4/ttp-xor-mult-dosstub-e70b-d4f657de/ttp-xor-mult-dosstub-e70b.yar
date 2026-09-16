rule TTP_XOR_MULT_DOSStub_e70b {
  strings:
    $key_e70b = { b3 63 [2] c7 7b [2] 80 79 [2] c7 68 [2] 89 64 [2] 85 6e [2] 92 65 [2] 89 2b [2] b4 }

  condition:
    any of them
}