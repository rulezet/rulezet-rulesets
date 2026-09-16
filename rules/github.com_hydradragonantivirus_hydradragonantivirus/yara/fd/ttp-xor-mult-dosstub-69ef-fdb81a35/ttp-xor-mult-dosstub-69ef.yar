rule TTP_XOR_MULT_DOSStub_69ef {
  strings:
    $key_69ef = { 3d 87 [2] 49 9f [2] 0e 9d [2] 49 8c [2] 07 80 [2] 0b 8a [2] 1c 81 [2] 07 cf [2] 3a }

  condition:
    any of them
}