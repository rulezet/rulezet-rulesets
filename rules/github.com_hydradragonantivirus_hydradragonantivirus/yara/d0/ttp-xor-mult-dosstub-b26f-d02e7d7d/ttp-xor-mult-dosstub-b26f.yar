rule TTP_XOR_MULT_DOSStub_b26f {
  strings:
    $key_b26f = { e6 07 [2] 92 1f [2] d5 1d [2] 92 0c [2] dc 00 [2] d0 0a [2] c7 01 [2] dc 4f [2] e1 }

  condition:
    any of them
}