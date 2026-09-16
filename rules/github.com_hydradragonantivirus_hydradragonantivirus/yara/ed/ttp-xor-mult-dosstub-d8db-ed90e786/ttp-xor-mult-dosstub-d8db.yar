rule TTP_XOR_MULT_DOSStub_d8db {
  strings:
    $key_d8db = { 8c b3 [2] f8 ab [2] bf a9 [2] f8 b8 [2] b6 b4 [2] ba be [2] ad b5 [2] b6 fb [2] 8b }

  condition:
    any of them
}