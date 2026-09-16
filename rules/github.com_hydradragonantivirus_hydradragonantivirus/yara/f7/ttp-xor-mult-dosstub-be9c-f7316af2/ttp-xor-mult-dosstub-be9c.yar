rule TTP_XOR_MULT_DOSStub_be9c {
  strings:
    $key_be9c = { ea f4 [2] 9e ec [2] d9 ee [2] 9e ff [2] d0 f3 [2] dc f9 [2] cb f2 [2] d0 bc [2] ed }

  condition:
    any of them
}