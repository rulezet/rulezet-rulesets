rule TTP_XOR_MULT_DOSStub_a963 {
  strings:
    $key_a963 = { fd 0b [2] 89 13 [2] ce 11 [2] 89 00 [2] c7 0c [2] cb 06 [2] dc 0d [2] c7 43 [2] fa }

  condition:
    any of them
}