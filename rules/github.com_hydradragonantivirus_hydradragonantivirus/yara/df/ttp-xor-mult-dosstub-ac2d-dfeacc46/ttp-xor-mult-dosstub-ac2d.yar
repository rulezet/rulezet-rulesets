rule TTP_XOR_MULT_DOSStub_ac2d {
  strings:
    $key_ac2d = { f8 45 [2] 8c 5d [2] cb 5f [2] 8c 4e [2] c2 42 [2] ce 48 [2] d9 43 [2] c2 0d [2] ff }

  condition:
    any of them
}