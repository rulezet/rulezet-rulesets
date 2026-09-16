rule TTP_XOR_MULT_DOSStub_e613 {
  strings:
    $key_e613 = { b2 7b [2] c6 63 [2] 81 61 [2] c6 70 [2] 88 7c [2] 84 76 [2] 93 7d [2] 88 33 [2] b5 }

  condition:
    any of them
}