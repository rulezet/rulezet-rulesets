rule TTP_XOR_MULT_DOSStub_286a {
  strings:
    $key_286a = { 7c 02 [2] 08 1a [2] 4f 18 [2] 08 09 [2] 46 05 [2] 4a 0f [2] 5d 04 [2] 46 4a [2] 7b }

  condition:
    any of them
}