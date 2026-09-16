rule TTP_XOR_MULT_DOSStub_e0fa {
  strings:
    $key_e0fa = { b4 92 [2] c0 8a [2] 87 88 [2] c0 99 [2] 8e 95 [2] 82 9f [2] 95 94 [2] 8e da [2] b3 }

  condition:
    any of them
}