rule TTP_XOR_MULT_DOSStub_bee1 {
  strings:
    $key_bee1 = { ea 89 [2] 9e 91 [2] d9 93 [2] 9e 82 [2] d0 8e [2] dc 84 [2] cb 8f [2] d0 c1 [2] ed }

  condition:
    any of them
}