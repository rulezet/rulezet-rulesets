rule TTP_XOR_MULT_DOSStub_74cd {
  strings:
    $key_74cd = { 20 a5 [2] 54 bd [2] 13 bf [2] 54 ae [2] 1a a2 [2] 16 a8 [2] 01 a3 [2] 1a ed [2] 27 }

  condition:
    any of them
}