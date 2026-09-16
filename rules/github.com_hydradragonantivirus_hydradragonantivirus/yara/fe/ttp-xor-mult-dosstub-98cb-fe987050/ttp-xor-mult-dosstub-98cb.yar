rule TTP_XOR_MULT_DOSStub_98cb {
  strings:
    $key_98cb = { cc a3 [2] b8 bb [2] ff b9 [2] b8 a8 [2] f6 a4 [2] fa ae [2] ed a5 [2] f6 eb [2] cb }

  condition:
    any of them
}