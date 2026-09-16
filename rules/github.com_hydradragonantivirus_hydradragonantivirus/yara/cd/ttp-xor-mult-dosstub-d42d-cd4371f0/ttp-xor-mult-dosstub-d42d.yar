rule TTP_XOR_MULT_DOSStub_d42d {
  strings:
    $key_d42d = { 80 45 [2] f4 5d [2] b3 5f [2] f4 4e [2] ba 42 [2] b6 48 [2] a1 43 [2] ba 0d [2] 87 }

  condition:
    any of them
}