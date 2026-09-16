rule TTP_XOR_MULT_DOSStub_be10 {
  strings:
    $key_be10 = { ea 78 [2] 9e 60 [2] d9 62 [2] 9e 73 [2] d0 7f [2] dc 75 [2] cb 7e [2] d0 30 [2] ed }

  condition:
    any of them
}