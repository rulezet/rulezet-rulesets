rule TTP_XOR_MULT_DOSStub_282f {
  strings:
    $key_282f = { 7c 47 [2] 08 5f [2] 4f 5d [2] 08 4c [2] 46 40 [2] 4a 4a [2] 5d 41 [2] 46 0f [2] 7b }

  condition:
    any of them
}