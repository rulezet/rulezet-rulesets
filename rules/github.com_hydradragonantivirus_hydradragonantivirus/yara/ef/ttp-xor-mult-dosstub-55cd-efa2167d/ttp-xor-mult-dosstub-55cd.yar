rule TTP_XOR_MULT_DOSStub_55cd {
  strings:
    $key_55cd = { 01 a5 [2] 75 bd [2] 32 bf [2] 75 ae [2] 3b a2 [2] 37 a8 [2] 20 a3 [2] 3b ed [2] 06 }

  condition:
    any of them
}