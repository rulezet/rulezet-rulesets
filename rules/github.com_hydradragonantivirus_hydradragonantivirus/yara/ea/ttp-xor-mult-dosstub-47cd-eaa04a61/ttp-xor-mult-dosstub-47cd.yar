rule TTP_XOR_MULT_DOSStub_47cd {
  strings:
    $key_47cd = { 13 a5 [2] 67 bd [2] 20 bf [2] 67 ae [2] 29 a2 [2] 25 a8 [2] 32 a3 [2] 29 ed [2] 14 }

  condition:
    any of them
}