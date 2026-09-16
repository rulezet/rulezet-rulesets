rule TTP_XOR_MULT_DOSStub_c251 {
  strings:
    $key_c251 = { 96 39 [2] e2 21 [2] a5 23 [2] e2 32 [2] ac 3e [2] a0 34 [2] b7 3f [2] ac 71 [2] 91 }

  condition:
    any of them
}