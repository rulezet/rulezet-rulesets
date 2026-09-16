rule TTP_XOR_MULT_DOSStub_bb6d {
  strings:
    $key_bb6d = { ef 05 [2] 9b 1d [2] dc 1f [2] 9b 0e [2] d5 02 [2] d9 08 [2] ce 03 [2] d5 4d [2] e8 }

  condition:
    any of them
}