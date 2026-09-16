rule TTP_XOR_MULT_DOSStub_2880 {
  strings:
    $key_2880 = { 7c e8 [2] 08 f0 [2] 4f f2 [2] 08 e3 [2] 46 ef [2] 4a e5 [2] 5d ee [2] 46 a0 [2] 7b }

  condition:
    any of them
}