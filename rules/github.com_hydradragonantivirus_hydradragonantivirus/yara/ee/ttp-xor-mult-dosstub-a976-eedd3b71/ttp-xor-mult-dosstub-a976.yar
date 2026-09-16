rule TTP_XOR_MULT_DOSStub_a976 {
  strings:
    $key_a976 = { fd 1e [2] 89 06 [2] ce 04 [2] 89 15 [2] c7 19 [2] cb 13 [2] dc 18 [2] c7 56 [2] fa }

  condition:
    any of them
}