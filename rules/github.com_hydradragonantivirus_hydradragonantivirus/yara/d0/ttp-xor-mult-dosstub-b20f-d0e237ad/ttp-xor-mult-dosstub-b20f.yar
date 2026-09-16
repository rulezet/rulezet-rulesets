rule TTP_XOR_MULT_DOSStub_b20f {
  strings:
    $key_b20f = { e6 67 [2] 92 7f [2] d5 7d [2] 92 6c [2] dc 60 [2] d0 6a [2] c7 61 [2] dc 2f [2] e1 }

  condition:
    any of them
}