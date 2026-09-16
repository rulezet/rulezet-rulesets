rule TTP_XOR_MULT_DOSStub_ac3d {
  strings:
    $key_ac3d = { f8 55 [2] 8c 4d [2] cb 4f [2] 8c 5e [2] c2 52 [2] ce 58 [2] d9 53 [2] c2 1d [2] ff }

  condition:
    any of them
}