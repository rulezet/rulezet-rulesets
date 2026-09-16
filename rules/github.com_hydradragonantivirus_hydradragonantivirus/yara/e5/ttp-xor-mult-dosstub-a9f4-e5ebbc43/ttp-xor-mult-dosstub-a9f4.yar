rule TTP_XOR_MULT_DOSStub_a9f4 {
  strings:
    $key_a9f4 = { fd 9c [2] 89 84 [2] ce 86 [2] 89 97 [2] c7 9b [2] cb 91 [2] dc 9a [2] c7 d4 [2] fa }

  condition:
    any of them
}