rule TTP_XOR_MULT_DOSStub_b20c {
  strings:
    $key_b20c = { e6 64 [2] 92 7c [2] d5 7e [2] 92 6f [2] dc 63 [2] d0 69 [2] c7 62 [2] dc 2c [2] e1 }

  condition:
    any of them
}