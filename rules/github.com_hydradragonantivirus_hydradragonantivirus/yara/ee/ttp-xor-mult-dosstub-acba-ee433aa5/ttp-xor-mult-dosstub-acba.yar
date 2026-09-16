rule TTP_XOR_MULT_DOSStub_acba {
  strings:
    $key_acba = { f8 d2 [2] 8c ca [2] cb c8 [2] 8c d9 [2] c2 d5 [2] ce df [2] d9 d4 [2] c2 9a [2] ff }

  condition:
    any of them
}