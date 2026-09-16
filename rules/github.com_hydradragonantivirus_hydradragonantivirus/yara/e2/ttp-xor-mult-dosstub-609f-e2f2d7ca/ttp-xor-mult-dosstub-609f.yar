rule TTP_XOR_MULT_DOSStub_609f {
  strings:
    $key_609f = { 34 f7 [2] 40 ef [2] 07 ed [2] 40 fc [2] 0e f0 [2] 02 fa [2] 15 f1 [2] 0e bf [2] 33 }

  condition:
    any of them
}