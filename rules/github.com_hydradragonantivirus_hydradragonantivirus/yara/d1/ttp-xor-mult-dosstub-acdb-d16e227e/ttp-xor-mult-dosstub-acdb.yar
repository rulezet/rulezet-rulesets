rule TTP_XOR_MULT_DOSStub_acdb {
  strings:
    $key_acdb = { f8 b3 [2] 8c ab [2] cb a9 [2] 8c b8 [2] c2 b4 [2] ce be [2] d9 b5 [2] c2 fb [2] ff }

  condition:
    any of them
}