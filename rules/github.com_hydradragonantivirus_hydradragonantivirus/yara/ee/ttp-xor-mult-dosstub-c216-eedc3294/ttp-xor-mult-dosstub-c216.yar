rule TTP_XOR_MULT_DOSStub_c216 {
  strings:
    $key_c216 = { 96 7e [2] e2 66 [2] a5 64 [2] e2 75 [2] ac 79 [2] a0 73 [2] b7 78 [2] ac 36 [2] 91 }

  condition:
    any of them
}