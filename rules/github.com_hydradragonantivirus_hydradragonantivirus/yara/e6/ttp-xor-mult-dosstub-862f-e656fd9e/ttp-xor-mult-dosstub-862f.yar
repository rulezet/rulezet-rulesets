rule TTP_XOR_MULT_DOSStub_862f {
  strings:
    $key_862f = { d2 47 [2] a6 5f [2] e1 5d [2] a6 4c [2] e8 40 [2] e4 4a [2] f3 41 [2] e8 0f [2] d5 }

  condition:
    any of them
}