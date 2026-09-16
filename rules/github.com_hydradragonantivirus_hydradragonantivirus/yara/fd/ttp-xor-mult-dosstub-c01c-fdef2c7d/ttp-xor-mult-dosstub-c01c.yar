rule TTP_XOR_MULT_DOSStub_c01c {
  strings:
    $key_c01c = { 94 74 [2] e0 6c [2] a7 6e [2] e0 7f [2] ae 73 [2] a2 79 [2] b5 72 [2] ae 3c [2] 93 }

  condition:
    any of them
}