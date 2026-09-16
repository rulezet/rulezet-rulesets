rule TTP_XOR_MULT_DOSStub_bb6a {
  strings:
    $key_bb6a = { ef 02 [2] 9b 1a [2] dc 18 [2] 9b 09 [2] d5 05 [2] d9 0f [2] ce 04 [2] d5 4a [2] e8 }

  condition:
    any of them
}