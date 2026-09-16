rule TTP_XOR_MULT_DOSStub_349f {
  strings:
    $key_349f = { 60 f7 [2] 14 ef [2] 53 ed [2] 14 fc [2] 5a f0 [2] 56 fa [2] 41 f1 [2] 5a bf [2] 67 }

  condition:
    any of them
}