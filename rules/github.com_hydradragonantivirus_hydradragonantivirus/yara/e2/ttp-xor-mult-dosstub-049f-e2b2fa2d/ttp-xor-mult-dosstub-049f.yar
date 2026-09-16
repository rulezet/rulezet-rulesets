rule TTP_XOR_MULT_DOSStub_049f {
  strings:
    $key_049f = { 50 f7 [2] 24 ef [2] 63 ed [2] 24 fc [2] 6a f0 [2] 66 fa [2] 71 f1 [2] 6a bf [2] 57 }

  condition:
    any of them
}