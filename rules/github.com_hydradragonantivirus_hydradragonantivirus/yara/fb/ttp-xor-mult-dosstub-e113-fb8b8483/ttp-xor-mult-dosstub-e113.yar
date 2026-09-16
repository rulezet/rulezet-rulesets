rule TTP_XOR_MULT_DOSStub_e113 {
  strings:
    $key_e113 = { b5 7b [2] c1 63 [2] 86 61 [2] c1 70 [2] 8f 7c [2] 83 76 [2] 94 7d [2] 8f 33 [2] b2 }

  condition:
    any of them
}