rule TTP_XOR_MULT_DOSStub_bbe9 {
  strings:
    $key_bbe9 = { ef 81 [2] 9b 99 [2] dc 9b [2] 9b 8a [2] d5 86 [2] d9 8c [2] ce 87 [2] d5 c9 [2] e8 }

  condition:
    any of them
}