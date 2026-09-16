rule TTP_XOR_MULT_DOSStub_bbe8 {
  strings:
    $key_bbe8 = { ef 80 [2] 9b 98 [2] dc 9a [2] 9b 8b [2] d5 87 [2] d9 8d [2] ce 86 [2] d5 c8 [2] e8 }

  condition:
    any of them
}