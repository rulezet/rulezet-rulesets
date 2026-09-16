rule TTP_XOR_MULT_DOSStub_97af {
  strings:
    $key_97af = { c3 c7 [2] b7 df [2] f0 dd [2] b7 cc [2] f9 c0 [2] f5 ca [2] e2 c1 [2] f9 8f [2] c4 }

  condition:
    any of them
}