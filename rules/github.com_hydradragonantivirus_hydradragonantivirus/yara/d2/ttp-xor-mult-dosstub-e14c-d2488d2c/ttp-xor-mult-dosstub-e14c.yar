rule TTP_XOR_MULT_DOSStub_e14c {
  strings:
    $key_e14c = { b5 24 [2] c1 3c [2] 86 3e [2] c1 2f [2] 8f 23 [2] 83 29 [2] 94 22 [2] 8f 6c [2] b2 }

  condition:
    any of them
}