rule TTP_XOR_MULT_DOSStub_d30d {
  strings:
    $key_d30d = { 87 65 [2] f3 7d [2] b4 7f [2] f3 6e [2] bd 62 [2] b1 68 [2] a6 63 [2] bd 2d [2] 80 }

  condition:
    any of them
}