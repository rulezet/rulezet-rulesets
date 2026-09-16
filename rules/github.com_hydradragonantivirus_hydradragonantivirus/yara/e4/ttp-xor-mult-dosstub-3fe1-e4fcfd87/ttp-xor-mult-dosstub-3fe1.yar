rule TTP_XOR_MULT_DOSStub_3fe1 {
  strings:
    $key_3fe1 = { 6b 89 [2] 1f 91 [2] 58 93 [2] 1f 82 [2] 51 8e [2] 5d 84 [2] 4a 8f [2] 51 c1 [2] 6c }

  condition:
    any of them
}