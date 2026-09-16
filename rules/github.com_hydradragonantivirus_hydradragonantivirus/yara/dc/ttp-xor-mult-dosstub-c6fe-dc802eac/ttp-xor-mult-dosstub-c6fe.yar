rule TTP_XOR_MULT_DOSStub_c6fe {
  strings:
    $key_c6fe = { 92 96 [2] e6 8e [2] a1 8c [2] e6 9d [2] a8 91 [2] a4 9b [2] b3 90 [2] a8 de [2] 95 }

  condition:
    any of them
}