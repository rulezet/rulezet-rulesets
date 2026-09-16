rule TTP_XOR_MULT_DOSStub_bb48 {
  strings:
    $key_bb48 = { ef 20 [2] 9b 38 [2] dc 3a [2] 9b 2b [2] d5 27 [2] d9 2d [2] ce 26 [2] d5 68 [2] e8 }

  condition:
    any of them
}