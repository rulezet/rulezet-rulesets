rule TTP_XOR_MULT_DOSStub_c7fe {
  strings:
    $key_c7fe = { 93 96 [2] e7 8e [2] a0 8c [2] e7 9d [2] a9 91 [2] a5 9b [2] b2 90 [2] a9 de [2] 94 }

  condition:
    any of them
}