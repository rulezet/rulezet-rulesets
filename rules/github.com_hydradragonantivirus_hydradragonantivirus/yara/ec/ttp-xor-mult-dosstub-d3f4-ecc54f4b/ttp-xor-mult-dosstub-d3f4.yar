rule TTP_XOR_MULT_DOSStub_d3f4 {
  strings:
    $key_d3f4 = { 87 9c [2] f3 84 [2] b4 86 [2] f3 97 [2] bd 9b [2] b1 91 [2] a6 9a [2] bd d4 [2] 80 }

  condition:
    any of them
}