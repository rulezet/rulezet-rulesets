rule TTP_XOR_MULT_DOSStub_a924 {
  strings:
    $key_a924 = { fd 4c [2] 89 54 [2] ce 56 [2] 89 47 [2] c7 4b [2] cb 41 [2] dc 4a [2] c7 04 [2] fa }

  condition:
    any of them
}