rule TTP_XOR_MULT_DOSStub_5af1 {
  strings:
    $key_5af1 = { 0e 99 [2] 7a 81 [2] 3d 83 [2] 7a 92 [2] 34 9e [2] 38 94 [2] 2f 9f [2] 34 d1 [2] 09 }

  condition:
    any of them
}