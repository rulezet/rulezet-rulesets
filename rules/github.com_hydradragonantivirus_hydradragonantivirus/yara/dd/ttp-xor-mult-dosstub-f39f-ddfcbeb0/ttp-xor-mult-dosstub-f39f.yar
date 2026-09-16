rule TTP_XOR_MULT_DOSStub_f39f {
  strings:
    $key_f39f = { a7 f7 [2] d3 ef [2] 94 ed [2] d3 fc [2] 9d f0 [2] 91 fa [2] 86 f1 [2] 9d bf [2] a0 }

  condition:
    any of them
}