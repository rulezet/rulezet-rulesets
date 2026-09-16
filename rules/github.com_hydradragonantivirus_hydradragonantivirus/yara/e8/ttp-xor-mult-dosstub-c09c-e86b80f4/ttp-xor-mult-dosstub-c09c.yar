rule TTP_XOR_MULT_DOSStub_c09c {
  strings:
    $key_c09c = { 94 f4 [2] e0 ec [2] a7 ee [2] e0 ff [2] ae f3 [2] a2 f9 [2] b5 f2 [2] ae bc [2] 93 }

  condition:
    any of them
}