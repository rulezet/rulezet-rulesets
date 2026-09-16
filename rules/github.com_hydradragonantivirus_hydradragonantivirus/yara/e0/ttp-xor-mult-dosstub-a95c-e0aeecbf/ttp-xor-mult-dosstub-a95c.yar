rule TTP_XOR_MULT_DOSStub_a95c {
  strings:
    $key_a95c = { fd 34 [2] 89 2c [2] ce 2e [2] 89 3f [2] c7 33 [2] cb 39 [2] dc 32 [2] c7 7c [2] fa }

  condition:
    any of them
}