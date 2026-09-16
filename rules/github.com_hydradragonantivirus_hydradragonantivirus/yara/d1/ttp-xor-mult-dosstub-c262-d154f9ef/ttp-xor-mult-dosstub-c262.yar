rule TTP_XOR_MULT_DOSStub_c262 {
  strings:
    $key_c262 = { 96 0a [2] e2 12 [2] a5 10 [2] e2 01 [2] ac 0d [2] a0 07 [2] b7 0c [2] ac 42 [2] 91 }

  condition:
    any of them
}