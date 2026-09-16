rule TTP_XOR_MULT_DOSStub_acea {
  strings:
    $key_acea = { f8 82 [2] 8c 9a [2] cb 98 [2] 8c 89 [2] c2 85 [2] ce 8f [2] d9 84 [2] c2 ca [2] ff }

  condition:
    any of them
}