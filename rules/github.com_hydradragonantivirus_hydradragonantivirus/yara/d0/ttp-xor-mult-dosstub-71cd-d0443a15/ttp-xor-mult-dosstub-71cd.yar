rule TTP_XOR_MULT_DOSStub_71cd {
  strings:
    $key_71cd = { 25 a5 [2] 51 bd [2] 16 bf [2] 51 ae [2] 1f a2 [2] 13 a8 [2] 04 a3 [2] 1f ed [2] 22 }

  condition:
    any of them
}