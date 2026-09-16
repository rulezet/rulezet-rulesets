rule TTP_XOR_MULT_DOSStub_94cd {
  strings:
    $key_94cd = { c0 a5 [2] b4 bd [2] f3 bf [2] b4 ae [2] fa a2 [2] f6 a8 [2] e1 a3 [2] fa ed [2] c7 }

  condition:
    any of them
}