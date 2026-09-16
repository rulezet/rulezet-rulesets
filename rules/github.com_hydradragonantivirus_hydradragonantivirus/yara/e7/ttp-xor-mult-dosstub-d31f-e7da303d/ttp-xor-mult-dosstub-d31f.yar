rule TTP_XOR_MULT_DOSStub_d31f {
  strings:
    $key_d31f = { 87 77 [2] f3 6f [2] b4 6d [2] f3 7c [2] bd 70 [2] b1 7a [2] a6 71 [2] bd 3f [2] 80 }

  condition:
    any of them
}