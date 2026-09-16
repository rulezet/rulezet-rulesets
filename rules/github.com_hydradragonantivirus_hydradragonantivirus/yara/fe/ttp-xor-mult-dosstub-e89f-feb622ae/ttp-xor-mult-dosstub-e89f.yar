rule TTP_XOR_MULT_DOSStub_e89f {
  strings:
    $key_e89f = { bc f7 [2] c8 ef [2] 8f ed [2] c8 fc [2] 86 f0 [2] 8a fa [2] 9d f1 [2] 86 bf [2] bb }

  condition:
    any of them
}