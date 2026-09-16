rule TTP_XOR_MULT_DOSStub_889c {
  strings:
    $key_889c = { dc f4 [2] a8 ec [2] ef ee [2] a8 ff [2] e6 f3 [2] ea f9 [2] fd f2 [2] e6 bc [2] db }

  condition:
    any of them
}