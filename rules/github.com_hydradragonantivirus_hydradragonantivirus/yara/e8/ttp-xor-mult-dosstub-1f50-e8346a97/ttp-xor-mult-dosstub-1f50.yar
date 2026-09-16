rule TTP_XOR_MULT_DOSStub_1f50 {
  strings:
    $key_1f50 = { 4b 38 [2] 3f 20 [2] 78 22 [2] 3f 33 [2] 71 3f [2] 7d 35 [2] 6a 3e [2] 71 70 [2] 4c }

  condition:
    any of them
}