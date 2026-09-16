rule TTP_XOR_MULT_DOSStub_eb1f {
  strings:
    $key_eb1f = { bf 77 [2] cb 6f [2] 8c 6d [2] cb 7c [2] 85 70 [2] 89 7a [2] 9e 71 [2] 85 3f [2] b8 }

  condition:
    any of them
}