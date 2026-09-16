rule TTP_XOR_MULT_DOSStub_46cd {
  strings:
    $key_46cd = { 12 a5 [2] 66 bd [2] 21 bf [2] 66 ae [2] 28 a2 [2] 24 a8 [2] 33 a3 [2] 28 ed [2] 15 }

  condition:
    any of them
}