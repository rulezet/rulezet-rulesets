rule TTP_XOR_MULT_DOSStub_7fe1 {
  strings:
    $key_7fe1 = { 2b 89 [2] 5f 91 [2] 18 93 [2] 5f 82 [2] 11 8e [2] 1d 84 [2] 0a 8f [2] 11 c1 [2] 2c }

  condition:
    any of them
}