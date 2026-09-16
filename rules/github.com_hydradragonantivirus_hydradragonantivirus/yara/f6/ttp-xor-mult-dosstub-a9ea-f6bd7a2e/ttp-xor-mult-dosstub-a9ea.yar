rule TTP_XOR_MULT_DOSStub_a9ea {
  strings:
    $key_a9ea = { fd 82 [2] 89 9a [2] ce 98 [2] 89 89 [2] c7 85 [2] cb 8f [2] dc 84 [2] c7 ca [2] fa }

  condition:
    any of them
}