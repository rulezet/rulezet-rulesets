rule TTP_XOR_MULT_DOSStub_292f {
  strings:
    $key_292f = { 7d 47 [2] 09 5f [2] 4e 5d [2] 09 4c [2] 47 40 [2] 4b 4a [2] 5c 41 [2] 47 0f [2] 7a }

  condition:
    any of them
}