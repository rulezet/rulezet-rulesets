rule TTP_XOR_MULT_DOSStub_c201 {
  strings:
    $key_c201 = { 96 69 [2] e2 71 [2] a5 73 [2] e2 62 [2] ac 6e [2] a0 64 [2] b7 6f [2] ac 21 [2] 91 }

  condition:
    any of them
}