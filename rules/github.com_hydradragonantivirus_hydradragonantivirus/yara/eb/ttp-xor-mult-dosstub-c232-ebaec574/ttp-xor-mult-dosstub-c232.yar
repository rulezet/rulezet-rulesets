rule TTP_XOR_MULT_DOSStub_c232 {
  strings:
    $key_c232 = { 96 5a [2] e2 42 [2] a5 40 [2] e2 51 [2] ac 5d [2] a0 57 [2] b7 5c [2] ac 12 [2] 91 }

  condition:
    any of them
}