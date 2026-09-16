rule TTP_XOR_WriteProcessMemory_1718 {
  strings:
    $key_1718 = { 40 6a [2] 72 48 [2] 74 7d [2] 5a 7d [2] 65 61 }

  condition:
    any of them
}