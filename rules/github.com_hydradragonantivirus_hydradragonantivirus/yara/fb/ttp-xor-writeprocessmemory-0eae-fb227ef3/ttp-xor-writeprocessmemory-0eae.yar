rule TTP_XOR_WriteProcessMemory_0eae {
  strings:
    $key_0eae = { 59 dc [2] 6b fe [2] 6d cb [2] 43 cb [2] 7c d7 }

  condition:
    any of them
}