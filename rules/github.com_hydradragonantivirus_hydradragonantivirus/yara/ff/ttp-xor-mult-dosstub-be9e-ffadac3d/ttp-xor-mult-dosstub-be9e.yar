rule TTP_XOR_MULT_DOSStub_be9e {
  strings:
    $key_be9e = { ea f6 [2] 9e ee [2] d9 ec [2] 9e fd [2] d0 f1 [2] dc fb [2] cb f0 [2] d0 be [2] ed }

  condition:
    any of them
}