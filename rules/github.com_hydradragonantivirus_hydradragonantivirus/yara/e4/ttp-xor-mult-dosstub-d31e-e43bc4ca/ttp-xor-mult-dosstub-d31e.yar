rule TTP_XOR_MULT_DOSStub_d31e {
  strings:
    $key_d31e = { 87 76 [2] f3 6e [2] b4 6c [2] f3 7d [2] bd 71 [2] b1 7b [2] a6 70 [2] bd 3e [2] 80 }

  condition:
    any of them
}