rule TTP_XOR_MULT_DOSStub_1fe1 {
  strings:
    $key_1fe1 = { 4b 89 [2] 3f 91 [2] 78 93 [2] 3f 82 [2] 71 8e [2] 7d 84 [2] 6a 8f [2] 71 c1 [2] 4c }

  condition:
    any of them
}