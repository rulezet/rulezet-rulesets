rule TTP_XOR_MULT_DOSStub_67cd {
  strings:
    $key_67cd = { 33 a5 [2] 47 bd [2] 00 bf [2] 47 ae [2] 09 a2 [2] 05 a8 [2] 12 a3 [2] 09 ed [2] 34 }

  condition:
    any of them
}