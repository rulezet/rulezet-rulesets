rule TTP_XOR_MULT_DOSStub_b27c {
  strings:
    $key_b27c = { e6 14 [2] 92 0c [2] d5 0e [2] 92 1f [2] dc 13 [2] d0 19 [2] c7 12 [2] dc 5c [2] e1 }

  condition:
    any of them
}