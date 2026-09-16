rule TTP_XOR_MULT_DOSStub_a9e3 {
  strings:
    $key_a9e3 = { fd 8b [2] 89 93 [2] ce 91 [2] 89 80 [2] c7 8c [2] cb 86 [2] dc 8d [2] c7 c3 [2] fa }

  condition:
    any of them
}