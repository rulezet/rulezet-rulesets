rule TTP_XOR_MULT_DOSStub_a960 {
  strings:
    $key_a960 = { fd 08 [2] 89 10 [2] ce 12 [2] 89 03 [2] c7 0f [2] cb 05 [2] dc 0e [2] c7 40 [2] fa }

  condition:
    any of them
}