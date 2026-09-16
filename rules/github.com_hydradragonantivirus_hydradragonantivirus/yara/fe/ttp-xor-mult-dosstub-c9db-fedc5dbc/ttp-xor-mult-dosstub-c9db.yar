rule TTP_XOR_MULT_DOSStub_c9db {
  strings:
    $key_c9db = { 9d b3 [2] e9 ab [2] ae a9 [2] e9 b8 [2] a7 b4 [2] ab be [2] bc b5 [2] a7 fb [2] 9a }

  condition:
    any of them
}