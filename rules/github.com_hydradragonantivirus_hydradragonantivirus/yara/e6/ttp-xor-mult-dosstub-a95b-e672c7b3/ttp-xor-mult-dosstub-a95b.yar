rule TTP_XOR_MULT_DOSStub_a95b {
  strings:
    $key_a95b = { fd 33 [2] 89 2b [2] ce 29 [2] 89 38 [2] c7 34 [2] cb 3e [2] dc 35 [2] c7 7b [2] fa }

  condition:
    any of them
}