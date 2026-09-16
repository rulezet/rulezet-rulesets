rule TTP_XOR_MULT_DOSStub_52cd {
  strings:
    $key_52cd = { 06 a5 [2] 72 bd [2] 35 bf [2] 72 ae [2] 3c a2 [2] 30 a8 [2] 27 a3 [2] 3c ed [2] 01 }

  condition:
    any of them
}