rule TTP_XOR_MULT_DOSStub_f2cd {
  strings:
    $key_f2cd = { a6 a5 [2] d2 bd [2] 95 bf [2] d2 ae [2] 9c a2 [2] 90 a8 [2] 87 a3 [2] 9c ed [2] a1 }

  condition:
    any of them
}