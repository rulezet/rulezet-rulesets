rule TTP_XOR_MULT_DOSStub_d34d {
  strings:
    $key_d34d = { 87 25 [2] f3 3d [2] b4 3f [2] f3 2e [2] bd 22 [2] b1 28 [2] a6 23 [2] bd 6d [2] 80 }

  condition:
    any of them
}