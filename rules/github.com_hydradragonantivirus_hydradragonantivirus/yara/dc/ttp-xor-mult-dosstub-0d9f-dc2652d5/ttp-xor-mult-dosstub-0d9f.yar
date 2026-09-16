rule TTP_XOR_MULT_DOSStub_0d9f {
  strings:
    $key_0d9f = { 59 f7 [2] 2d ef [2] 6a ed [2] 2d fc [2] 63 f0 [2] 6f fa [2] 78 f1 [2] 63 bf [2] 5e }

  condition:
    any of them
}