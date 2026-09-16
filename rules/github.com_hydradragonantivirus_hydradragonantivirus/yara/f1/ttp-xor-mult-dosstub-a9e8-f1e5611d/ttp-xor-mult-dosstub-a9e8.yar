rule TTP_XOR_MULT_DOSStub_a9e8 {
  strings:
    $key_a9e8 = { fd 80 [2] 89 98 [2] ce 9a [2] 89 8b [2] c7 87 [2] cb 8d [2] dc 86 [2] c7 c8 [2] fa }

  condition:
    any of them
}