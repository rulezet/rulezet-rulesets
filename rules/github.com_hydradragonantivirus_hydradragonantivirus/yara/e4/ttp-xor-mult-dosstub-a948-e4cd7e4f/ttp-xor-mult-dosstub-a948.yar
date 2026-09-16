rule TTP_XOR_MULT_DOSStub_a948 {
  strings:
    $key_a948 = { fd 20 [2] 89 38 [2] ce 3a [2] 89 2b [2] c7 27 [2] cb 2d [2] dc 26 [2] c7 68 [2] fa }

  condition:
    any of them
}