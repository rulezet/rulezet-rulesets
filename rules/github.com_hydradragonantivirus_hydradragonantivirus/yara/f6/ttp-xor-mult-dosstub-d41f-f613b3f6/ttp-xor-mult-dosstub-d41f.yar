rule TTP_XOR_MULT_DOSStub_d41f {
  strings:
    $key_d41f = { 80 77 [2] f4 6f [2] b3 6d [2] f4 7c [2] ba 70 [2] b6 7a [2] a1 71 [2] ba 3f [2] 87 }

  condition:
    any of them
}