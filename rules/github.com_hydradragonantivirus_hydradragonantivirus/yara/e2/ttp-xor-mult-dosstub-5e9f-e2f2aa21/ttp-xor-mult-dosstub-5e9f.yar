rule TTP_XOR_MULT_DOSStub_5e9f {
  strings:
    $key_5e9f = { 0a f7 [2] 7e ef [2] 39 ed [2] 7e fc [2] 30 f0 [2] 3c fa [2] 2b f1 [2] 30 bf [2] 0d }

  condition:
    any of them
}