rule TTP_XOR_MULT_DOSStub_c99f {
  strings:
    $key_c99f = { 9d f7 [2] e9 ef [2] ae ed [2] e9 fc [2] a7 f0 [2] ab fa [2] bc f1 [2] a7 bf [2] 9a }

  condition:
    any of them
}