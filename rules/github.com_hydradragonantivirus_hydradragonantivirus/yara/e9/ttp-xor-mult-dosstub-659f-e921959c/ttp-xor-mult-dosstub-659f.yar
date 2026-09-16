rule TTP_XOR_MULT_DOSStub_659f {
  strings:
    $key_659f = { 31 f7 [2] 45 ef [2] 02 ed [2] 45 fc [2] 0b f0 [2] 07 fa [2] 10 f1 [2] 0b bf [2] 36 }

  condition:
    any of them
}