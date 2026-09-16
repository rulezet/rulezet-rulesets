rule TTP_XOR_MULT_DOSStub_be8e {
  strings:
    $key_be8e = { ea e6 [2] 9e fe [2] d9 fc [2] 9e ed [2] d0 e1 [2] dc eb [2] cb e0 [2] d0 ae [2] ed }

  condition:
    any of them
}