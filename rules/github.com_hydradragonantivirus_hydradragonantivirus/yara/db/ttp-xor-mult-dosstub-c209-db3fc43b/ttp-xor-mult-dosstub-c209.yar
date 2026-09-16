rule TTP_XOR_MULT_DOSStub_c209 {
  strings:
    $key_c209 = { 96 61 [2] e2 79 [2] a5 7b [2] e2 6a [2] ac 66 [2] a0 6c [2] b7 67 [2] ac 29 [2] 91 }

  condition:
    any of them
}