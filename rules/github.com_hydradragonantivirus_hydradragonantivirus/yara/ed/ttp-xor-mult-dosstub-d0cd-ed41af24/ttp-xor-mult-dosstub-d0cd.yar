rule TTP_XOR_MULT_DOSStub_d0cd {
  strings:
    $key_d0cd = { 84 a5 [2] f0 bd [2] b7 bf [2] f0 ae [2] be a2 [2] b2 a8 [2] a5 a3 [2] be ed [2] 83 }

  condition:
    any of them
}