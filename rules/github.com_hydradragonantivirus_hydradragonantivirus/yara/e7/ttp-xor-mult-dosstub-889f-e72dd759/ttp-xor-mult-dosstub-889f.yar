rule TTP_XOR_MULT_DOSStub_889f {
  strings:
    $key_889f = { dc f7 [2] a8 ef [2] ef ed [2] a8 fc [2] e6 f0 [2] ea fa [2] fd f1 [2] e6 bf [2] db }

  condition:
    any of them
}