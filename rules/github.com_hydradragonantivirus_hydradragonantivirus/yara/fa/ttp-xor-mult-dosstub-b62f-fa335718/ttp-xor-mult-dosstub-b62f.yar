rule TTP_XOR_MULT_DOSStub_b62f {
  strings:
    $key_b62f = { e2 47 [2] 96 5f [2] d1 5d [2] 96 4c [2] d8 40 [2] d4 4a [2] c3 41 [2] d8 0f [2] e5 }

  condition:
    any of them
}