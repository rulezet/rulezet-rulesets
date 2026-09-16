rule TTP_XOR_MULT_DOSStub_04cd {
  strings:
    $key_04cd = { 50 a5 [2] 24 bd [2] 63 bf [2] 24 ae [2] 6a a2 [2] 66 a8 [2] 71 a3 [2] 6a ed [2] 57 }

  condition:
    any of them
}