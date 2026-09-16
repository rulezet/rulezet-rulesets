rule TTP_XOR_MULT_DOSStub_88a8 {
  strings:
    $key_88a8 = { dc c0 [2] a8 d8 [2] ef da [2] a8 cb [2] e6 c7 [2] ea cd [2] fd c6 [2] e6 88 [2] db }

  condition:
    any of them
}