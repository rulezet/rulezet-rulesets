rule TTP_XOR_MULT_DOSStub_dd07 {
  strings:
    $key_dd07 = { 89 6f [2] fd 77 [2] ba 75 [2] fd 64 [2] b3 68 [2] bf 62 [2] a8 69 [2] b3 27 [2] 8e }

  condition:
    any of them
}