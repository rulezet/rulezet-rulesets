rule TTP_XOR_MULT_DOSStub_7e9f {
  strings:
    $key_7e9f = { 2a f7 [2] 5e ef [2] 19 ed [2] 5e fc [2] 10 f0 [2] 1c fa [2] 0b f1 [2] 10 bf [2] 2d }

  condition:
    any of them
}