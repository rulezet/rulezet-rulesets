rule TTP_XOR_MULT_DOSStub_9bc7 {
  strings:
    $key_9bc7 = { cf af [2] bb b7 [2] fc b5 [2] bb a4 [2] f5 a8 [2] f9 a2 [2] ee a9 [2] f5 e7 [2] c8 }

  condition:
    any of them
}