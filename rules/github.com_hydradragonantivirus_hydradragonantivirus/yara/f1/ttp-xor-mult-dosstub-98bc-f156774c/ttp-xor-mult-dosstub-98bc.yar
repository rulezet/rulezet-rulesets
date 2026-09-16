rule TTP_XOR_MULT_DOSStub_98bc {
  strings:
    $key_98bc = { cc d4 [2] b8 cc [2] ff ce [2] b8 df [2] f6 d3 [2] fa d9 [2] ed d2 [2] f6 9c [2] cb }

  condition:
    any of them
}