rule TTP_XOR_MULT_DOSStub_e129 {
  strings:
    $key_e129 = { b5 41 [2] c1 59 [2] 86 5b [2] c1 4a [2] 8f 46 [2] 83 4c [2] 94 47 [2] 8f 09 [2] b2 }

  condition:
    any of them
}