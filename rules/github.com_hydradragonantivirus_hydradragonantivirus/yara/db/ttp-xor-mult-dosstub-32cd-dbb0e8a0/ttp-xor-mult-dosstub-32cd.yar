rule TTP_XOR_MULT_DOSStub_32cd {
  strings:
    $key_32cd = { 66 a5 [2] 12 bd [2] 55 bf [2] 12 ae [2] 5c a2 [2] 50 a8 [2] 47 a3 [2] 5c ed [2] 61 }

  condition:
    any of them
}