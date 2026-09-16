rule TTP_XOR_MULT_DOSStub_bb64 {
  strings:
    $key_bb64 = { ef 0c [2] 9b 14 [2] dc 16 [2] 9b 07 [2] d5 0b [2] d9 01 [2] ce 0a [2] d5 44 [2] e8 }

  condition:
    any of them
}