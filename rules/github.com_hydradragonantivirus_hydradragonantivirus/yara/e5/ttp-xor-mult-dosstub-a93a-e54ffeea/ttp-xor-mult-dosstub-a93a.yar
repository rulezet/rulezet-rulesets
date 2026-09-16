rule TTP_XOR_MULT_DOSStub_a93a {
  strings:
    $key_a93a = { fd 52 [2] 89 4a [2] ce 48 [2] 89 59 [2] c7 55 [2] cb 5f [2] dc 54 [2] c7 1a [2] fa }

  condition:
    any of them
}