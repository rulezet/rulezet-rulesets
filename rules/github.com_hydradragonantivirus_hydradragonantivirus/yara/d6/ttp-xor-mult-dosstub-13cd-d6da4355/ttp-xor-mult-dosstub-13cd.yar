rule TTP_XOR_MULT_DOSStub_13cd {
  strings:
    $key_13cd = { 47 a5 [2] 33 bd [2] 74 bf [2] 33 ae [2] 7d a2 [2] 71 a8 [2] 66 a3 [2] 7d ed [2] 40 }

  condition:
    any of them
}