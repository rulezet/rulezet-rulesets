rule TTP_XOR_MULT_DOSStub_ec8a {
  strings:
    $key_ec8a = { b8 e2 [2] cc fa [2] 8b f8 [2] cc e9 [2] 82 e5 [2] 8e ef [2] 99 e4 [2] 82 aa [2] bf }

  condition:
    any of them
}