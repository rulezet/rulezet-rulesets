rule TTP_XOR_MULT_DOSStub_35cd {
  strings:
    $key_35cd = { 61 a5 [2] 15 bd [2] 52 bf [2] 15 ae [2] 5b a2 [2] 57 a8 [2] 40 a3 [2] 5b ed [2] 66 }

  condition:
    any of them
}