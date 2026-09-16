rule TTP_XOR_MULT_DOSStub_e109 {
  strings:
    $key_e109 = { b5 61 [2] c1 79 [2] 86 7b [2] c1 6a [2] 8f 66 [2] 83 6c [2] 94 67 [2] 8f 29 [2] b2 }

  condition:
    any of them
}