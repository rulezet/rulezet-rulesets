rule TTP_XOR_MULT_DOSStub_2fef {
  strings:
    $key_2fef = { 7b 87 [2] 0f 9f [2] 48 9d [2] 0f 8c [2] 41 80 [2] 4d 8a [2] 5a 81 [2] 41 cf [2] 7c }

  condition:
    any of them
}