rule TTP_XOR_MULT_DOSStub_c5ef {
  strings:
    $key_c5ef = { 91 87 [2] e5 9f [2] a2 9d [2] e5 8c [2] ab 80 [2] a7 8a [2] b0 81 [2] ab cf [2] 96 }

  condition:
    any of them
}