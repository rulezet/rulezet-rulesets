rule TTP_XOR_MULT_DOSStub_96cd {
  strings:
    $key_96cd = { c2 a5 [2] b6 bd [2] f1 bf [2] b6 ae [2] f8 a2 [2] f4 a8 [2] e3 a3 [2] f8 ed [2] c5 }

  condition:
    any of them
}