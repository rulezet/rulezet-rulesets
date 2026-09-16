rule TTP_XOR_MULT_DOSStub_e1fc {
  strings:
    $key_e1fc = { b5 94 [2] c1 8c [2] 86 8e [2] c1 9f [2] 8f 93 [2] 83 99 [2] 94 92 [2] 8f dc [2] b2 }

  condition:
    any of them
}