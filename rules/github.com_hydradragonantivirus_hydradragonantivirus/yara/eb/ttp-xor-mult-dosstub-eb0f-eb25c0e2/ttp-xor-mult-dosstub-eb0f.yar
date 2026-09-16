rule TTP_XOR_MULT_DOSStub_eb0f {
  strings:
    $key_eb0f = { bf 67 [2] cb 7f [2] 8c 7d [2] cb 6c [2] 85 60 [2] 89 6a [2] 9e 61 [2] 85 2f [2] b8 }

  condition:
    any of them
}