rule TTP_XOR_MULT_DOSStub_a925 {
  strings:
    $key_a925 = { fd 4d [2] 89 55 [2] ce 57 [2] 89 46 [2] c7 4a [2] cb 40 [2] dc 4b [2] c7 05 [2] fa }

  condition:
    any of them
}