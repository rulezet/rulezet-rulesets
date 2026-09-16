rule TTP_XOR_MULT_DOSStub_a3cd {
  strings:
    $key_a3cd = { f7 a5 [2] 83 bd [2] c4 bf [2] 83 ae [2] cd a2 [2] c1 a8 [2] d6 a3 [2] cd ed [2] f0 }

  condition:
    any of them
}