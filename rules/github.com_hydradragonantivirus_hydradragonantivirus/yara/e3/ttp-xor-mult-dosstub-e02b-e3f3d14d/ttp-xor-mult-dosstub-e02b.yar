rule TTP_XOR_MULT_DOSStub_e02b {
  strings:
    $key_e02b = { b4 43 [2] c0 5b [2] 87 59 [2] c0 48 [2] 8e 44 [2] 82 4e [2] 95 45 [2] 8e 0b [2] b3 }

  condition:
    any of them
}