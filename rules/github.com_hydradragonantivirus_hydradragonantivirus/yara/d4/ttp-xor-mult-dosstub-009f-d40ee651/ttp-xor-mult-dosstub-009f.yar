rule TTP_XOR_MULT_DOSStub_009f {
  strings:
    $key_009f = { 54 f7 [2] 20 ef [2] 67 ed [2] 20 fc [2] 6e f0 [2] 62 fa [2] 75 f1 [2] 6e bf [2] 53 }

  condition:
    any of them
}