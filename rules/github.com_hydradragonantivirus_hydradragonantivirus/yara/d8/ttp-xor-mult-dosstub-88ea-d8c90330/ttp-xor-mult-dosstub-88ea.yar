rule TTP_XOR_MULT_DOSStub_88ea {
  strings:
    $key_88ea = { dc 82 [2] a8 9a [2] ef 98 [2] a8 89 [2] e6 85 [2] ea 8f [2] fd 84 [2] e6 ca [2] db }

  condition:
    any of them
}