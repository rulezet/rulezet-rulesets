rule TTP_XOR_MULT_DOSStub_95fd {
  strings:
    $key_95fd = { c1 95 [2] b5 8d [2] f2 8f [2] b5 9e [2] fb 92 [2] f7 98 [2] e0 93 [2] fb dd [2] c6 }

  condition:
    any of them
}