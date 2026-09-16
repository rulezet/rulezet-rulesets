rule TTP_XOR_MULT_DOSStub_e125 {
  strings:
    $key_e125 = { b5 4d [2] c1 55 [2] 86 57 [2] c1 46 [2] 8f 4a [2] 83 40 [2] 94 4b [2] 8f 05 [2] b2 }

  condition:
    any of them
}