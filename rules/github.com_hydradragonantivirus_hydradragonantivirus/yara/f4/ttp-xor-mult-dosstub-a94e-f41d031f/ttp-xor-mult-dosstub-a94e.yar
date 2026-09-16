rule TTP_XOR_MULT_DOSStub_a94e {
  strings:
    $key_a94e = { fd 26 [2] 89 3e [2] ce 3c [2] 89 2d [2] c7 21 [2] cb 2b [2] dc 20 [2] c7 6e [2] fa }

  condition:
    any of them
}