rule TTP_XOR_MULT_DOSStub_c2f8 {
  strings:
    $key_c2f8 = { 96 90 [2] e2 88 [2] a5 8a [2] e2 9b [2] ac 97 [2] a0 9d [2] b7 96 [2] ac d8 [2] 91 }

  condition:
    any of them
}