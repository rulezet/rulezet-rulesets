rule TTP_XOR_MULT_DOSStub_a92c {
  strings:
    $key_a92c = { fd 44 [2] 89 5c [2] ce 5e [2] 89 4f [2] c7 43 [2] cb 49 [2] dc 42 [2] c7 0c [2] fa }

  condition:
    any of them
}