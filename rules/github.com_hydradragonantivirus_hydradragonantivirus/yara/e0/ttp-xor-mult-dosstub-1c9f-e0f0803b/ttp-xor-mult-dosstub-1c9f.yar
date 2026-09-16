rule TTP_XOR_MULT_DOSStub_1c9f {
  strings:
    $key_1c9f = { 48 f7 [2] 3c ef [2] 7b ed [2] 3c fc [2] 72 f0 [2] 7e fa [2] 69 f1 [2] 72 bf [2] 4f }

  condition:
    any of them
}