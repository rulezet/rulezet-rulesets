rule TTP_XOR_MULT_DOSStub_73cd {
  strings:
    $key_73cd = { 27 a5 [2] 53 bd [2] 14 bf [2] 53 ae [2] 1d a2 [2] 11 a8 [2] 06 a3 [2] 1d ed [2] 20 }

  condition:
    any of them
}