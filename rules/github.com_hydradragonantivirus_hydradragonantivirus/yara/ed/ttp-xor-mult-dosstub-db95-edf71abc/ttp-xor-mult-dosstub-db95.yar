rule TTP_XOR_MULT_DOSStub_db95 {
  strings:
    $key_db95 = { 8f fd [2] fb e5 [2] bc e7 [2] fb f6 [2] b5 fa [2] b9 f0 [2] ae fb [2] b5 b5 [2] 88 }

  condition:
    any of them
}