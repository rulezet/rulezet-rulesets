rule TTP_XOR_MULT_DOSStub_a9dc {
  strings:
    $key_a9dc = { fd b4 [2] 89 ac [2] ce ae [2] 89 bf [2] c7 b3 [2] cb b9 [2] dc b2 [2] c7 fc [2] fa }

  condition:
    any of them
}