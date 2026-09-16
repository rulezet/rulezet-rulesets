rule TTP_XOR_MULT_DOSStub_229f {
  strings:
    $key_229f = { 76 f7 [2] 02 ef [2] 45 ed [2] 02 fc [2] 4c f0 [2] 40 fa [2] 57 f1 [2] 4c bf [2] 71 }

  condition:
    any of them
}