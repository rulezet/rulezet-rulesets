rule TTP_XOR_MULT_DOSStub_ac6f {
  strings:
    $key_ac6f = { f8 07 [2] 8c 1f [2] cb 1d [2] 8c 0c [2] c2 00 [2] ce 0a [2] d9 01 [2] c2 4f [2] ff }

  condition:
    any of them
}