rule TTP_XOR_MULT_DOSStub_a9fe {
  strings:
    $key_a9fe = { fd 96 [2] 89 8e [2] ce 8c [2] 89 9d [2] c7 91 [2] cb 9b [2] dc 90 [2] c7 de [2] fa }

  condition:
    any of them
}