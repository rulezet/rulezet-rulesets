rule TTP_XOR_MULT_DOSStub_696a {
  strings:
    $key_696a = { 3d 02 [2] 49 1a [2] 0e 18 [2] 49 09 [2] 07 05 [2] 0b 0f [2] 1c 04 [2] 07 4a [2] 3a }

  condition:
    any of them
}