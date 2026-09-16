rule TTP_XOR_WriteProcessMemory_4eae {
  strings:
    $key_4eae = { 19 dc [2] 2b fe [2] 2d cb [2] 03 cb [2] 3c d7 }

  condition:
    any of them
}