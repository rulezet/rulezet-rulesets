rule TTP_XOR_MULT_DOSStub_a97d {
  strings:
    $key_a97d = { fd 15 [2] 89 0d [2] ce 0f [2] 89 1e [2] c7 12 [2] cb 18 [2] dc 13 [2] c7 5d [2] fa }

  condition:
    any of them
}