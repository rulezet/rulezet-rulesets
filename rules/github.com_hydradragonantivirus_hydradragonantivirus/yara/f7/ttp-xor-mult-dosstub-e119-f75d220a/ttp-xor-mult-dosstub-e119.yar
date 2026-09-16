rule TTP_XOR_MULT_DOSStub_e119 {
  strings:
    $key_e119 = { b5 71 [2] c1 69 [2] 86 6b [2] c1 7a [2] 8f 76 [2] 83 7c [2] 94 77 [2] 8f 39 [2] b2 }

  condition:
    any of them
}