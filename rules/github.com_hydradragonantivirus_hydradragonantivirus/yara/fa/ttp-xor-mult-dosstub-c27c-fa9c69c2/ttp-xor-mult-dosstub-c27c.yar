rule TTP_XOR_MULT_DOSStub_c27c {
  strings:
    $key_c27c = { 96 14 [2] e2 0c [2] a5 0e [2] e2 1f [2] ac 13 [2] a0 19 [2] b7 12 [2] ac 5c [2] 91 }

  condition:
    any of them
}