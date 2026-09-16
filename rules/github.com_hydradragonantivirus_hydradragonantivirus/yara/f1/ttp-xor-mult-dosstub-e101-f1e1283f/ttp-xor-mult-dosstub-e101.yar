rule TTP_XOR_MULT_DOSStub_e101 {
  strings:
    $key_e101 = { b5 69 [2] c1 71 [2] 86 73 [2] c1 62 [2] 8f 6e [2] 83 64 [2] 94 6f [2] 8f 21 [2] b2 }

  condition:
    any of them
}