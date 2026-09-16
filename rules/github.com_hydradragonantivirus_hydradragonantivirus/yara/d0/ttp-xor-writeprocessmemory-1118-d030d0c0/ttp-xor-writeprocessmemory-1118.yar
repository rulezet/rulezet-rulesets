rule TTP_XOR_WriteProcessMemory_1118 {
  strings:
    $key_1118 = { 46 6a [2] 74 48 [2] 72 7d [2] 5c 7d [2] 63 61 }

  condition:
    any of them
}