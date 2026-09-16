rule TTP_XOR_MULT_DOSStub_6929 {
  strings:
    $key_6929 = { 3d 41 [2] 49 59 [2] 0e 5b [2] 49 4a [2] 07 46 [2] 0b 4c [2] 1c 47 [2] 07 09 [2] 3a }

  condition:
    any of them
}