rule TTP_XOR_MULT_DOSStub_1ee1 {
  strings:
    $key_1ee1 = { 4a 89 [2] 3e 91 [2] 79 93 [2] 3e 82 [2] 70 8e [2] 7c 84 [2] 6b 8f [2] 70 c1 [2] 4d }

  condition:
    any of them
}