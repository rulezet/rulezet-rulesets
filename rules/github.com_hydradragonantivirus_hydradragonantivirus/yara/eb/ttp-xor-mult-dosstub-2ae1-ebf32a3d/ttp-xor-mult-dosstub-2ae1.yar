rule TTP_XOR_MULT_DOSStub_2ae1 {
  strings:
    $key_2ae1 = { 7e 89 [2] 0a 91 [2] 4d 93 [2] 0a 82 [2] 44 8e [2] 48 84 [2] 5f 8f [2] 44 c1 [2] 79 }

  condition:
    any of them
}