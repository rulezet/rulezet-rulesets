rule TTP_XOR_MULT_DOSStub_86fd {
  strings:
    $key_86fd = { d2 95 [2] a6 8d [2] e1 8f [2] a6 9e [2] e8 92 [2] e4 98 [2] f3 93 [2] e8 dd [2] d5 }

  condition:
    any of them
}