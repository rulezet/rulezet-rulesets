rule TTP_XOR_WriteProcessMemory_625f {
  strings:
    $key_625f = { 35 2d [2] 07 0f [2] 01 3a [2] 2f 3a [2] 10 26 }

  condition:
    any of them
}