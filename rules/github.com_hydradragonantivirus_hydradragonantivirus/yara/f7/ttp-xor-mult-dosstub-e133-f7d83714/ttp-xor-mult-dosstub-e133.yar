rule TTP_XOR_MULT_DOSStub_e133 {
  strings:
    $key_e133 = { b5 5b [2] c1 43 [2] 86 41 [2] c1 50 [2] 8f 5c [2] 83 56 [2] 94 5d [2] 8f 13 [2] b2 }

  condition:
    any of them
}