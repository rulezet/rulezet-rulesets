rule TTP_XOR_MULT_DOSStub_a907 {
  strings:
    $key_a907 = { fd 6f [2] 89 77 [2] ce 75 [2] 89 64 [2] c7 68 [2] cb 62 [2] dc 69 [2] c7 27 [2] fa }

  condition:
    any of them
}