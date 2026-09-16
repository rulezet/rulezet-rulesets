rule TTP_XOR_MULT_DOSStub_a909 {
  strings:
    $key_a909 = { fd 61 [2] 89 79 [2] ce 7b [2] 89 6a [2] c7 66 [2] cb 6c [2] dc 67 [2] c7 29 [2] fa }

  condition:
    any of them
}