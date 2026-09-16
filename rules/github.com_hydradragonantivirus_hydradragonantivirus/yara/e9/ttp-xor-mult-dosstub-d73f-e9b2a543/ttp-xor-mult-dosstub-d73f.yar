rule TTP_XOR_MULT_DOSStub_d73f {
  strings:
    $key_d73f = { 83 57 [2] f7 4f [2] b0 4d [2] f7 5c [2] b9 50 [2] b5 5a [2] a2 51 [2] b9 1f [2] 84 }

  condition:
    any of them
}