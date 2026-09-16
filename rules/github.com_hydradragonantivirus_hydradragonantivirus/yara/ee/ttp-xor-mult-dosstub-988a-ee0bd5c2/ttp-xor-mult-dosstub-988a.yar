rule TTP_XOR_MULT_DOSStub_988a {
  strings:
    $key_988a = { cc e2 [2] b8 fa [2] ff f8 [2] b8 e9 [2] f6 e5 [2] fa ef [2] ed e4 [2] f6 aa [2] cb }

  condition:
    any of them
}