rule TTP_XOR_MULT_DOSStub_c7fd {
  strings:
    $key_c7fd = { 93 95 [2] e7 8d [2] a0 8f [2] e7 9e [2] a9 92 [2] a5 98 [2] b2 93 [2] a9 dd [2] 94 }

  condition:
    any of them
}