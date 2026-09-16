rule TTP_XOR_MULT_DOSStub_886c {
  strings:
    $key_886c = { dc 04 [2] a8 1c [2] ef 1e [2] a8 0f [2] e6 03 [2] ea 09 [2] fd 02 [2] e6 4c [2] db }

  condition:
    any of them
}