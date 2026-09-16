rule TTP_XOR_MULT_DOSStub_2df0 {
  strings:
    $key_2df0 = { 79 98 [2] 0d 80 [2] 4a 82 [2] 0d 93 [2] 43 9f [2] 4f 95 [2] 58 9e [2] 43 d0 [2] 7e }

  condition:
    any of them
}