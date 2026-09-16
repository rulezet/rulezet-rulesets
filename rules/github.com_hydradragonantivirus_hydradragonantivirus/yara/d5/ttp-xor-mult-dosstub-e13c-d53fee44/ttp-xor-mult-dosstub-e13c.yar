rule TTP_XOR_MULT_DOSStub_e13c {
  strings:
    $key_e13c = { b5 54 [2] c1 4c [2] 86 4e [2] c1 5f [2] 8f 53 [2] 83 59 [2] 94 52 [2] 8f 1c [2] b2 }

  condition:
    any of them
}