rule TTP_XOR_MULT_DOSStub_b2fc {
  strings:
    $key_b2fc = { e6 94 [2] 92 8c [2] d5 8e [2] 92 9f [2] dc 93 [2] d0 99 [2] c7 92 [2] dc dc [2] e1 }

  condition:
    any of them
}