rule TTP_XOR_MULT_DOSStub_ef6a {
  strings:
    $key_ef6a = { bb 02 [2] cf 1a [2] 88 18 [2] cf 09 [2] 81 05 [2] 8d 0f [2] 9a 04 [2] 81 4a [2] bc }

  condition:
    any of them
}