rule TTP_XOR_MULT_DOSStub_a917 {
  strings:
    $key_a917 = { fd 7f [2] 89 67 [2] ce 65 [2] 89 74 [2] c7 78 [2] cb 72 [2] dc 79 [2] c7 37 [2] fa }

  condition:
    any of them
}