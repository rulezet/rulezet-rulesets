rule TTP_XOR_MULT_DOSStub_91cd {
  strings:
    $key_91cd = { c5 a5 [2] b1 bd [2] f6 bf [2] b1 ae [2] ff a2 [2] f3 a8 [2] e4 a3 [2] ff ed [2] c2 }

  condition:
    any of them
}