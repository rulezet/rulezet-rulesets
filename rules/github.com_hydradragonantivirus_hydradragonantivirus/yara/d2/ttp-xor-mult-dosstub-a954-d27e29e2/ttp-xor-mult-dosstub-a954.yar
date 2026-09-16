rule TTP_XOR_MULT_DOSStub_a954 {
  strings:
    $key_a954 = { fd 3c [2] 89 24 [2] ce 26 [2] 89 37 [2] c7 3b [2] cb 31 [2] dc 3a [2] c7 74 [2] fa }

  condition:
    any of them
}