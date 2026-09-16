rule TTP_XOR_MULT_DOSStub_e3ef {
  strings:
    $key_e3ef = { b7 87 [2] c3 9f [2] 84 9d [2] c3 8c [2] 8d 80 [2] 81 8a [2] 96 81 [2] 8d cf [2] b0 }

  condition:
    any of them
}