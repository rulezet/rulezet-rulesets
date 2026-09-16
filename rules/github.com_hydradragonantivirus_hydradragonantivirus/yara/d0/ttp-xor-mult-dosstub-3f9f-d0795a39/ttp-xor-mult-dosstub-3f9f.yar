rule TTP_XOR_MULT_DOSStub_3f9f {
  strings:
    $key_3f9f = { 6b f7 [2] 1f ef [2] 58 ed [2] 1f fc [2] 51 f0 [2] 5d fa [2] 4a f1 [2] 51 bf [2] 6c }

  condition:
    any of them
}