rule TTP_XOR_MULT_DOSStub_50cd {
  strings:
    $key_50cd = { 04 a5 [2] 70 bd [2] 37 bf [2] 70 ae [2] 3e a2 [2] 32 a8 [2] 25 a3 [2] 3e ed [2] 03 }

  condition:
    any of them
}