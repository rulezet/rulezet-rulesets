rule TTP_XOR_MULT_DOSStub_cfcd {
  strings:
    $key_cfcd = { 9b a5 [2] ef bd [2] a8 bf [2] ef ae [2] a1 a2 [2] ad a8 [2] ba a3 [2] a1 ed [2] 9c }

  condition:
    any of them
}