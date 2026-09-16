rule TTP_XOR_MULT_DOSStub_d8cd {
  strings:
    $key_d8cd = { 8c a5 [2] f8 bd [2] bf bf [2] f8 ae [2] b6 a2 [2] ba a8 [2] ad a3 [2] b6 ed [2] 8b }

  condition:
    any of them
}