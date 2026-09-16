rule TTP_XOR_MULT_DOSStub_b24d {
  strings:
    $key_b24d = { e6 25 [2] 92 3d [2] d5 3f [2] 92 2e [2] dc 22 [2] d0 28 [2] c7 23 [2] dc 6d [2] e1 }

  condition:
    any of them
}