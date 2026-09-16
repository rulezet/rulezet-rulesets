rule TTP_XOR_MULT_DOSStub_a9db {
  strings:
    $key_a9db = { fd b3 [2] 89 ab [2] ce a9 [2] 89 b8 [2] c7 b4 [2] cb be [2] dc b5 [2] c7 fb [2] fa }

  condition:
    any of them
}