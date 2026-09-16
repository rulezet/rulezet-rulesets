rule TTP_XOR_MULT_DOSStub_92af {
  strings:
    $key_92af = { c6 c7 [2] b2 df [2] f5 dd [2] b2 cc [2] fc c0 [2] f0 ca [2] e7 c1 [2] fc 8f [2] c1 }

  condition:
    any of them
}