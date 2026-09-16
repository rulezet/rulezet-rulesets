rule TTP_XOR_MULT_DOSStub_a933 {
  strings:
    $key_a933 = { fd 5b [2] 89 43 [2] ce 41 [2] 89 50 [2] c7 5c [2] cb 56 [2] dc 5d [2] c7 13 [2] fa }

  condition:
    any of them
}