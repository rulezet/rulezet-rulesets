rule TTP_XOR_MULT_DOSStub_08e1 {
  strings:
    $key_08e1 = { 5c 89 [2] 28 91 [2] 6f 93 [2] 28 82 [2] 66 8e [2] 6a 84 [2] 7d 8f [2] 66 c1 [2] 5b }

  condition:
    any of them
}