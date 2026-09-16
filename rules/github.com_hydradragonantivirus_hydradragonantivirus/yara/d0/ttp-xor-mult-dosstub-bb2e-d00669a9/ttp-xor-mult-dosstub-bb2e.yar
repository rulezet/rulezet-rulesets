rule TTP_XOR_MULT_DOSStub_bb2e {
  strings:
    $key_bb2e = { ef 46 [2] 9b 5e [2] dc 5c [2] 9b 4d [2] d5 41 [2] d9 4b [2] ce 40 [2] d5 0e [2] e8 }

  condition:
    any of them
}