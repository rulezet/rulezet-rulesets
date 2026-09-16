rule TTP_XOR_MULT_DOSStub_d63d {
  strings:
    $key_d63d = { 82 55 [2] f6 4d [2] b1 4f [2] f6 5e [2] b8 52 [2] b4 58 [2] a3 53 [2] b8 1d [2] 85 }

  condition:
    any of them
}