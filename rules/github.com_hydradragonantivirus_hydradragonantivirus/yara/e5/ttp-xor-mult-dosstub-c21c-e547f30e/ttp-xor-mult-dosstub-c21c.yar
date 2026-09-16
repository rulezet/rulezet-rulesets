rule TTP_XOR_MULT_DOSStub_c21c {
  strings:
    $key_c21c = { 96 74 [2] e2 6c [2] a5 6e [2] e2 7f [2] ac 73 [2] a0 79 [2] b7 72 [2] ac 3c [2] 91 }

  condition:
    any of them
}