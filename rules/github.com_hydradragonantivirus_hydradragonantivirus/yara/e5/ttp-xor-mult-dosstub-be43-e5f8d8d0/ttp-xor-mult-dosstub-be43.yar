rule TTP_XOR_MULT_DOSStub_be43 {
  strings:
    $key_be43 = { ea 2b [2] 9e 33 [2] d9 31 [2] 9e 20 [2] d0 2c [2] dc 26 [2] cb 2d [2] d0 63 [2] ed }

  condition:
    any of them
}