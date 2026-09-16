rule TTP_XOR_WriteProcessMemory_1028 {
  strings:
    $key_1028 = { 47 5a [2] 75 78 [2] 73 4d [2] 5d 4d [2] 62 51 }

  condition:
    any of them
}