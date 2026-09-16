rule TTP_XOR_MULT_DOSStub_c248 {
  strings:
    $key_c248 = { 96 20 [2] e2 38 [2] a5 3a [2] e2 2b [2] ac 27 [2] a0 2d [2] b7 26 [2] ac 68 [2] 91 }

  condition:
    any of them
}