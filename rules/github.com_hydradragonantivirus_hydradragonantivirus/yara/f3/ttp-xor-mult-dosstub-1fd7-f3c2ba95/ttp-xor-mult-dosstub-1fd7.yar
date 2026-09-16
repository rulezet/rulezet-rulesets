rule TTP_XOR_MULT_DOSStub_1fd7 {
  strings:
    $key_1fd7 = { 4b bf [2] 3f a7 [2] 78 a5 [2] 3f b4 [2] 71 b8 [2] 7d b2 [2] 6a b9 [2] 71 f7 [2] 4c }

  condition:
    any of them
}