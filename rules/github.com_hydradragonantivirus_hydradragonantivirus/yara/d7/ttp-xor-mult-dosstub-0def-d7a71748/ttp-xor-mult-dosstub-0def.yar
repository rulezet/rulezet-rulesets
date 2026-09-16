rule TTP_XOR_MULT_DOSStub_0def {
  strings:
    $key_0def = { 59 87 [2] 2d 9f [2] 6a 9d [2] 2d 8c [2] 63 80 [2] 6f 8a [2] 78 81 [2] 63 cf [2] 5e }

  condition:
    any of them
}