rule TTP_XOR_MULT_DOSStub_1fd0 {
  strings:
    $key_1fd0 = { 4b b8 [2] 3f a0 [2] 78 a2 [2] 3f b3 [2] 71 bf [2] 7d b5 [2] 6a be [2] 71 f0 [2] 4c }

  condition:
    any of them
}