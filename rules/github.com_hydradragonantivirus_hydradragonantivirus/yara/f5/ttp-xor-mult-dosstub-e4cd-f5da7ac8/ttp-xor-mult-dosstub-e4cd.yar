rule TTP_XOR_MULT_DOSStub_e4cd {
  strings:
    $key_e4cd = { b0 a5 [2] c4 bd [2] 83 bf [2] c4 ae [2] 8a a2 [2] 86 a8 [2] 91 a3 [2] 8a ed [2] b7 }

  condition:
    any of them
}