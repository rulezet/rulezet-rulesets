rule TTP_XOR_MULT_DOSStub_572f {
  strings:
    $key_572f = { 03 47 [2] 77 5f [2] 30 5d [2] 77 4c [2] 39 40 [2] 35 4a [2] 22 41 [2] 39 0f [2] 04 }

  condition:
    any of them
}