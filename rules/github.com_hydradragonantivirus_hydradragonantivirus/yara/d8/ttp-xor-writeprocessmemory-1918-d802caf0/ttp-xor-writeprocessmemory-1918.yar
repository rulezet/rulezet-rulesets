rule TTP_XOR_WriteProcessMemory_1918 {
  strings:
    $key_1918 = { 4e 6a [2] 7c 48 [2] 7a 7d [2] 54 7d [2] 6b 61 }

  condition:
    any of them
}