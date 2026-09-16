rule TTP_XOR_MULT_DOSStub_8e6a {
  strings:
    $key_8e6a = { da 02 [2] ae 1a [2] e9 18 [2] ae 09 [2] e0 05 [2] ec 0f [2] fb 04 [2] e0 4a [2] dd }

  condition:
    any of them
}