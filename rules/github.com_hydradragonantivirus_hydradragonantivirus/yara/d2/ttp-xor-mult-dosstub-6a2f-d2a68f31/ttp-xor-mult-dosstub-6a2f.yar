rule TTP_XOR_MULT_DOSStub_6a2f {
  strings:
    $key_6a2f = { 3e 47 [2] 4a 5f [2] 0d 5d [2] 4a 4c [2] 04 40 [2] 08 4a [2] 1f 41 [2] 04 0f [2] 39 }

  condition:
    any of them
}