rule TTP_XOR_MULT_DOSStub_e2ef {
  strings:
    $key_e2ef = { b6 87 [2] c2 9f [2] 85 9d [2] c2 8c [2] 8c 80 [2] 80 8a [2] 97 81 [2] 8c cf [2] b1 }

  condition:
    any of them
}