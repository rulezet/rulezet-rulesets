rule TTP_XOR_MULT_DOSStub_d30c {
  strings:
    $key_d30c = { 87 64 [2] f3 7c [2] b4 7e [2] f3 6f [2] bd 63 [2] b1 69 [2] a6 62 [2] bd 2c [2] 80 }

  condition:
    any of them
}