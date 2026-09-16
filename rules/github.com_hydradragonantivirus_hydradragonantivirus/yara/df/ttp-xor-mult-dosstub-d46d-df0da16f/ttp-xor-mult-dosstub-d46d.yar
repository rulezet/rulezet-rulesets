rule TTP_XOR_MULT_DOSStub_d46d {
  strings:
    $key_d46d = { 80 05 [2] f4 1d [2] b3 1f [2] f4 0e [2] ba 02 [2] b6 08 [2] a1 03 [2] ba 4d [2] 87 }

  condition:
    any of them
}