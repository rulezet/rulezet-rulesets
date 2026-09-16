rule TTP_XOR_MULT_DOSStub_e016 {
  strings:
    $key_e016 = { b4 7e [2] c0 66 [2] 87 64 [2] c0 75 [2] 8e 79 [2] 82 73 [2] 95 78 [2] 8e 36 [2] b3 }

  condition:
    any of them
}