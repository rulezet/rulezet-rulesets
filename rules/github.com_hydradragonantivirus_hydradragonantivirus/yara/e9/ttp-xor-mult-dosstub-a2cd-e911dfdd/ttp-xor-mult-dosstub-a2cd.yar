rule TTP_XOR_MULT_DOSStub_a2cd {
  strings:
    $key_a2cd = { f6 a5 [2] 82 bd [2] c5 bf [2] 82 ae [2] cc a2 [2] c0 a8 [2] d7 a3 [2] cc ed [2] f1 }

  condition:
    any of them
}