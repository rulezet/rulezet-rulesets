rule TTP_XOR_MULT_DOSStub_bb3f {
  strings:
    $key_bb3f = { ef 57 [2] 9b 4f [2] dc 4d [2] 9b 5c [2] d5 50 [2] d9 5a [2] ce 51 [2] d5 1f [2] e8 }

  condition:
    any of them
}