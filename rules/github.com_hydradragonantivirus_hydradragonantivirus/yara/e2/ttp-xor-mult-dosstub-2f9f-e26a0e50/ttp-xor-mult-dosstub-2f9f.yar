rule TTP_XOR_MULT_DOSStub_2f9f {
  strings:
    $key_2f9f = { 7b f7 [2] 0f ef [2] 48 ed [2] 0f fc [2] 41 f0 [2] 4d fa [2] 5a f1 [2] 41 bf [2] 7c }

  condition:
    any of them
}