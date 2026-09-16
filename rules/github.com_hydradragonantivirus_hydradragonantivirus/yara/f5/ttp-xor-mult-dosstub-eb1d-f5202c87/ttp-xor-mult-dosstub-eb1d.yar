rule TTP_XOR_MULT_DOSStub_eb1d {
  strings:
    $key_eb1d = { bf 75 [2] cb 6d [2] 8c 6f [2] cb 7e [2] 85 72 [2] 89 78 [2] 9e 73 [2] 85 3d [2] b8 }

  condition:
    any of them
}