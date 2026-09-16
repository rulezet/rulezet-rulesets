rule TTP_XOR_MULT_DOSStub_c239 {
  strings:
    $key_c239 = { 96 51 [2] e2 49 [2] a5 4b [2] e2 5a [2] ac 56 [2] a0 5c [2] b7 57 [2] ac 19 [2] 91 }

  condition:
    any of them
}