rule TTP_XOR_MULT_DOSStub_c236 {
  strings:
    $key_c236 = { 96 5e [2] e2 46 [2] a5 44 [2] e2 55 [2] ac 59 [2] a0 53 [2] b7 58 [2] ac 16 [2] 91 }

  condition:
    any of them
}