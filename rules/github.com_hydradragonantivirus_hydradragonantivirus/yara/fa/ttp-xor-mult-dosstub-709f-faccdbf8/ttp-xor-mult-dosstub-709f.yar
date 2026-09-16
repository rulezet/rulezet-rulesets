rule TTP_XOR_MULT_DOSStub_709f {
  strings:
    $key_709f = { 24 f7 [2] 50 ef [2] 17 ed [2] 50 fc [2] 1e f0 [2] 12 fa [2] 05 f1 [2] 1e bf [2] 23 }

  condition:
    any of them
}