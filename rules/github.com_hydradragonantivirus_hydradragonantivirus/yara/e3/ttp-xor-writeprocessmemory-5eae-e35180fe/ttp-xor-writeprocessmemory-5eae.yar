rule TTP_XOR_WriteProcessMemory_5eae {
  strings:
    $key_5eae = { 09 dc [2] 3b fe [2] 3d cb [2] 13 cb [2] 2c d7 }

  condition:
    any of them
}