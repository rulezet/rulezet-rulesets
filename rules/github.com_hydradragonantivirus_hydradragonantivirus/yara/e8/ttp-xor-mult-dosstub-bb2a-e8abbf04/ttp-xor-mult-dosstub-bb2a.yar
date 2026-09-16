rule TTP_XOR_MULT_DOSStub_bb2a {
  strings:
    $key_bb2a = { ef 42 [2] 9b 5a [2] dc 58 [2] 9b 49 [2] d5 45 [2] d9 4f [2] ce 44 [2] d5 0a [2] e8 }

  condition:
    any of them
}