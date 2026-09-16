rule TTP_XOR_MULT_DOSStub_a9ff {
  strings:
    $key_a9ff = { fd 97 [2] 89 8f [2] ce 8d [2] 89 9c [2] c7 90 [2] cb 9a [2] dc 91 [2] c7 df [2] fa }

  condition:
    any of them
}