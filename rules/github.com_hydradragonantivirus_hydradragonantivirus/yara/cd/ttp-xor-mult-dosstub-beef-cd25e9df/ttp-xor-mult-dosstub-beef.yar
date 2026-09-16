rule TTP_XOR_MULT_DOSStub_beef {
  strings:
    $key_beef = { ea 87 [2] 9e 9f [2] d9 9d [2] 9e 8c [2] d0 80 [2] dc 8a [2] cb 81 [2] d0 cf [2] ed }

  condition:
    any of them
}