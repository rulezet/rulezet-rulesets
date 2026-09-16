rule TTP_XOR_MULT_DOSStub_b3cd {
  strings:
    $key_b3cd = { e7 a5 [2] 93 bd [2] d4 bf [2] 93 ae [2] dd a2 [2] d1 a8 [2] c6 a3 [2] dd ed [2] e0 }

  condition:
    any of them
}