rule TTP_XOR_MULT_DOSStub_88da {
  strings:
    $key_88da = { dc b2 [2] a8 aa [2] ef a8 [2] a8 b9 [2] e6 b5 [2] ea bf [2] fd b4 [2] e6 fa [2] db }

  condition:
    any of them
}