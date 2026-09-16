rule TTP_XOR_MULT_DOSStub_d3ad {
  strings:
    $key_d3ad = { 87 c5 [2] f3 dd [2] b4 df [2] f3 ce [2] bd c2 [2] b1 c8 [2] a6 c3 [2] bd 8d [2] 80 }

  condition:
    any of them
}