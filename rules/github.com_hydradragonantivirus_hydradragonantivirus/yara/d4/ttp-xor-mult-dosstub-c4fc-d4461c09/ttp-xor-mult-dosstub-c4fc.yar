rule TTP_XOR_MULT_DOSStub_c4fc {
  strings:
    $key_c4fc = { 90 94 [2] e4 8c [2] a3 8e [2] e4 9f [2] aa 93 [2] a6 99 [2] b1 92 [2] aa dc [2] 97 }

  condition:
    any of them
}