rule TTP_XOR_MULT_DOSStub_486a {
  strings:
    $key_486a = { 1c 02 [2] 68 1a [2] 2f 18 [2] 68 09 [2] 26 05 [2] 2a 0f [2] 3d 04 [2] 26 4a [2] 1b }

  condition:
    any of them
}