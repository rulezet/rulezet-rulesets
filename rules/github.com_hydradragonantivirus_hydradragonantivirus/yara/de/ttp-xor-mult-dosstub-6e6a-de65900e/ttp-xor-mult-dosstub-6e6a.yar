rule TTP_XOR_MULT_DOSStub_6e6a {
  strings:
    $key_6e6a = { 3a 02 [2] 4e 1a [2] 09 18 [2] 4e 09 [2] 00 05 [2] 0c 0f [2] 1b 04 [2] 00 4a [2] 3d }

  condition:
    any of them
}