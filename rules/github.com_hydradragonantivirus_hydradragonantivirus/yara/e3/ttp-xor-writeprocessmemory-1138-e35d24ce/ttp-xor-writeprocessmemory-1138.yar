rule TTP_XOR_WriteProcessMemory_1138 {
  strings:
    $key_1138 = { 46 4a [2] 74 68 [2] 72 5d [2] 5c 5d [2] 63 41 }

  condition:
    any of them
}