rule TTP_XOR_MULT_DOSStub_eb2f {
  strings:
    $key_eb2f = { bf 47 [2] cb 5f [2] 8c 5d [2] cb 4c [2] 85 40 [2] 89 4a [2] 9e 41 [2] 85 0f [2] b8 }

  condition:
    any of them
}