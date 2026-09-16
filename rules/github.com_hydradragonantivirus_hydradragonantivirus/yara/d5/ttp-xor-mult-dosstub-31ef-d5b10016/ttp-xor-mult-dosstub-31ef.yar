rule TTP_XOR_MULT_DOSStub_31ef {
  strings:
    $key_31ef = { 65 87 [2] 11 9f [2] 56 9d [2] 11 8c [2] 5f 80 [2] 53 8a [2] 44 81 [2] 5f cf [2] 62 }

  condition:
    any of them
}