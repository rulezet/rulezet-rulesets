rule TTP_XOR_MULT_DOSStub_a97c {
  strings:
    $key_a97c = { fd 14 [2] 89 0c [2] ce 0e [2] 89 1f [2] c7 13 [2] cb 19 [2] dc 12 [2] c7 5c [2] fa }

  condition:
    any of them
}