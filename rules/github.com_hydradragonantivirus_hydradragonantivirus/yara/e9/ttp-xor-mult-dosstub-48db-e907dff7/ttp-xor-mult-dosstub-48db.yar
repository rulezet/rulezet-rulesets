rule TTP_XOR_MULT_DOSStub_48db {
  strings:
    $key_48db = { 1c b3 [2] 68 ab [2] 2f a9 [2] 68 b8 [2] 26 b4 [2] 2a be [2] 3d b5 [2] 26 fb [2] 1b }

  condition:
    any of them
}