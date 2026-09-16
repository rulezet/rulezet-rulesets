rule TTP_XOR_MULT_DOSStub_ac7f {
  strings:
    $key_ac7f = { f8 17 [2] 8c 0f [2] cb 0d [2] 8c 1c [2] c2 10 [2] ce 1a [2] d9 11 [2] c2 5f [2] ff }

  condition:
    any of them
}