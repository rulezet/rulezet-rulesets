rule TTP_XOR_WriteProcessMemory_1bf8 {
  strings:
    $key_1bf8 = { 4c 8a [2] 7e a8 [2] 78 9d [2] 56 9d [2] 69 81 }

  condition:
    any of them
}