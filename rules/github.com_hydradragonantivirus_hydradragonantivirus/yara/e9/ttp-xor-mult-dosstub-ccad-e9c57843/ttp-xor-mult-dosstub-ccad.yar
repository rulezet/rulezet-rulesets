rule TTP_XOR_MULT_DOSStub_ccad {
  strings:
    $key_ccad = { 98 c5 [2] ec dd [2] ab df [2] ec ce [2] a2 c2 [2] ae c8 [2] b9 c3 [2] a2 8d [2] 9f }

  condition:
    any of them
}