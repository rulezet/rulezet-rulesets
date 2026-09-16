rule TTP_XOR_MULT_DOSStub_a956 {
  strings:
    $key_a956 = { fd 3e [2] 89 26 [2] ce 24 [2] 89 35 [2] c7 39 [2] cb 33 [2] dc 38 [2] c7 76 [2] fa }

  condition:
    any of them
}