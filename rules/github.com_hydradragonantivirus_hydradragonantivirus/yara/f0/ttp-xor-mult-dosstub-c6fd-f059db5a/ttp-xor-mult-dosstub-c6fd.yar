rule TTP_XOR_MULT_DOSStub_c6fd {
  strings:
    $key_c6fd = { 92 95 [2] e6 8d [2] a1 8f [2] e6 9e [2] a8 92 [2] a4 98 [2] b3 93 [2] a8 dd [2] 95 }

  condition:
    any of them
}