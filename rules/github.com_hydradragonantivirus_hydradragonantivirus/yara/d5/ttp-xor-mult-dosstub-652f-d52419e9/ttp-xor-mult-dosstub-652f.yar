rule TTP_XOR_MULT_DOSStub_652f {
  strings:
    $key_652f = { 31 47 [2] 45 5f [2] 02 5d [2] 45 4c [2] 0b 40 [2] 07 4a [2] 10 41 [2] 0b 0f [2] 36 }

  condition:
    any of them
}