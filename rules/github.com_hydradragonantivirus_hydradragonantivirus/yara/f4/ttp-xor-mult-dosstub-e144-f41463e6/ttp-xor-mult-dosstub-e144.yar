rule TTP_XOR_MULT_DOSStub_e144 {
  strings:
    $key_e144 = { b5 2c [2] c1 34 [2] 86 36 [2] c1 27 [2] 8f 2b [2] 83 21 [2] 94 2a [2] 8f 64 [2] b2 }

  condition:
    any of them
}