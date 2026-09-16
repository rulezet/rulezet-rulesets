rule TTP_XOR_MULT_DOSStub_a930 {
  strings:
    $key_a930 = { fd 58 [2] 89 40 [2] ce 42 [2] 89 53 [2] c7 5f [2] cb 55 [2] dc 5e [2] c7 10 [2] fa }

  condition:
    any of them
}