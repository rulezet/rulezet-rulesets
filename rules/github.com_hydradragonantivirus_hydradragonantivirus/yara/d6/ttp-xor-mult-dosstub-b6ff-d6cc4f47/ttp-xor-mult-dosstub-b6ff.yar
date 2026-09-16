rule TTP_XOR_MULT_DOSStub_b6ff {
  strings:
    $key_b6ff = { e2 97 [2] 96 8f [2] d1 8d [2] 96 9c [2] d8 90 [2] d4 9a [2] c3 91 [2] d8 df [2] e5 }

  condition:
    any of them
}