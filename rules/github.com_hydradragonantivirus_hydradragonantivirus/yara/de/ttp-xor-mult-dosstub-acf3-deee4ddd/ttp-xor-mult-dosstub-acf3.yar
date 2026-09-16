rule TTP_XOR_MULT_DOSStub_acf3 {
  strings:
    $key_acf3 = { f8 9b [2] 8c 83 [2] cb 81 [2] 8c 90 [2] c2 9c [2] ce 96 [2] d9 9d [2] c2 d3 [2] ff }

  condition:
    any of them
}