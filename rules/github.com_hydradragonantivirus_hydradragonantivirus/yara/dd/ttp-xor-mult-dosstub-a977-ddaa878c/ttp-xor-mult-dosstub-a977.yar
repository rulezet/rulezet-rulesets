rule TTP_XOR_MULT_DOSStub_a977 {
  strings:
    $key_a977 = { fd 1f [2] 89 07 [2] ce 05 [2] 89 14 [2] c7 18 [2] cb 12 [2] dc 19 [2] c7 57 [2] fa }

  condition:
    any of them
}