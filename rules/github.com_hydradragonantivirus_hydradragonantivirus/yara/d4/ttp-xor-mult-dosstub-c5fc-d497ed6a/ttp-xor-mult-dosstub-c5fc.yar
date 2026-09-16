rule TTP_XOR_MULT_DOSStub_c5fc {
  strings:
    $key_c5fc = { 91 94 [2] e5 8c [2] a2 8e [2] e5 9f [2] ab 93 [2] a7 99 [2] b0 92 [2] ab dc [2] 96 }

  condition:
    any of them
}