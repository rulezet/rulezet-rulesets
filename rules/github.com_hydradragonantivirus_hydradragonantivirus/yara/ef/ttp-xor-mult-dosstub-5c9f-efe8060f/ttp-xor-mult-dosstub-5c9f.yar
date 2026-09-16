rule TTP_XOR_MULT_DOSStub_5c9f {
  strings:
    $key_5c9f = { 08 f7 [2] 7c ef [2] 3b ed [2] 7c fc [2] 32 f0 [2] 3e fa [2] 29 f1 [2] 32 bf [2] 0f }

  condition:
    any of them
}