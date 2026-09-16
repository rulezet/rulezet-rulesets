rule TTP_XOR_MULT_DOSStub_a967 {
  strings:
    $key_a967 = { fd 0f [2] 89 17 [2] ce 15 [2] 89 04 [2] c7 08 [2] cb 02 [2] dc 09 [2] c7 47 [2] fa }

  condition:
    any of them
}