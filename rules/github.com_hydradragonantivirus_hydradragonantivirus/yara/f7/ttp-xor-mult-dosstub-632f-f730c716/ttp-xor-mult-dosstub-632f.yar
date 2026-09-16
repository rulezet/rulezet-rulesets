rule TTP_XOR_MULT_DOSStub_632f {
  strings:
    $key_632f = { 37 47 [2] 43 5f [2] 04 5d [2] 43 4c [2] 0d 40 [2] 01 4a [2] 16 41 [2] 0d 0f [2] 30 }

  condition:
    any of them
}