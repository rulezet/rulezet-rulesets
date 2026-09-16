rule TTP_XOR_MULT_DOSStub_b23d {
  strings:
    $key_b23d = { e6 55 [2] 92 4d [2] d5 4f [2] 92 5e [2] dc 52 [2] d0 58 [2] c7 53 [2] dc 1d [2] e1 }

  condition:
    any of them
}