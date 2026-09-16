rule TTP_XOR_MULT_DOSStub_dda2 {
  strings:
    $key_dda2 = { 89 ca [2] fd d2 [2] ba d0 [2] fd c1 [2] b3 cd [2] bf c7 [2] a8 cc [2] b3 82 [2] 8e }

  condition:
    any of them
}