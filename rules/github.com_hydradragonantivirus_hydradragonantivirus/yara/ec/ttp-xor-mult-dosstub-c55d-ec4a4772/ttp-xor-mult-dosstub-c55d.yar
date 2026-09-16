rule TTP_XOR_MULT_DOSStub_c55d {
  strings:
    $key_c55d = { 91 35 [2] e5 2d [2] a2 2f [2] e5 3e [2] ab 32 [2] a7 38 [2] b0 33 [2] ab 7d [2] 96 }

  condition:
    any of them
}