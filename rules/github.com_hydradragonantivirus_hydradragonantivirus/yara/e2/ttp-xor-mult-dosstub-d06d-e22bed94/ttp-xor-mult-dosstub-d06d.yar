rule TTP_XOR_MULT_DOSStub_d06d {
  strings:
    $key_d06d = { 84 05 [2] f0 1d [2] b7 1f [2] f0 0e [2] be 02 [2] b2 08 [2] a5 03 [2] be 4d [2] 83 }

  condition:
    any of them
}