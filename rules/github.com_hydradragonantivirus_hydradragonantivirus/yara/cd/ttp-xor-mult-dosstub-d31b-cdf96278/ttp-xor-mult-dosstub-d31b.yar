rule TTP_XOR_MULT_DOSStub_d31b {
  strings:
    $key_d31b = { 87 73 [2] f3 6b [2] b4 69 [2] f3 78 [2] bd 74 [2] b1 7e [2] a6 75 [2] bd 3b [2] 80 }

  condition:
    any of them
}