rule TTP_XOR_MULT_DOSStub_1ef0 {
  strings:
    $key_1ef0 = { 4a 98 [2] 3e 80 [2] 79 82 [2] 3e 93 [2] 70 9f [2] 7c 95 [2] 6b 9e [2] 70 d0 [2] 4d }

  condition:
    any of them
}