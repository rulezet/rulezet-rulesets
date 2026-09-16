rule TTP_XOR_MULT_DOSStub_c25c {
  strings:
    $key_c25c = { 96 34 [2] e2 2c [2] a5 2e [2] e2 3f [2] ac 33 [2] a0 39 [2] b7 32 [2] ac 7c [2] 91 }

  condition:
    any of them
}