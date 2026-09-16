rule TTP_XOR_MULT_DOSStub_c14c {
  strings:
    $key_c14c = { 95 24 [2] e1 3c [2] a6 3e [2] e1 2f [2] af 23 [2] a3 29 [2] b4 22 [2] af 6c [2] 92 }

  condition:
    any of them
}