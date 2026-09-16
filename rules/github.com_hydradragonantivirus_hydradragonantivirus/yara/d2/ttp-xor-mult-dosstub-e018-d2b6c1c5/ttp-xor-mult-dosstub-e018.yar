rule TTP_XOR_MULT_DOSStub_e018 {
  strings:
    $key_e018 = { b4 70 [2] c0 68 [2] 87 6a [2] c0 7b [2] 8e 77 [2] 82 7d [2] 95 76 [2] 8e 38 [2] b3 }

  condition:
    any of them
}