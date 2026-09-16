rule TTP_XOR_MULT_DOSStub_d6af {
  strings:
    $key_d6af = { 82 c7 [2] f6 df [2] b1 dd [2] f6 cc [2] b8 c0 [2] b4 ca [2] a3 c1 [2] b8 8f [2] 85 }

  condition:
    any of them
}