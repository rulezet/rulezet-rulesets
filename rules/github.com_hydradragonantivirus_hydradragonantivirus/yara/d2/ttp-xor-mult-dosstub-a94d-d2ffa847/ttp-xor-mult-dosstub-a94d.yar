rule TTP_XOR_MULT_DOSStub_a94d {
  strings:
    $key_a94d = { fd 25 [2] 89 3d [2] ce 3f [2] 89 2e [2] c7 22 [2] cb 28 [2] dc 23 [2] c7 6d [2] fa }

  condition:
    any of them
}