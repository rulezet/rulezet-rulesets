rule TTP_XOR_WriteProcessMemory_08ac {
  strings:
    $key_08ac = { 5f de [2] 6d fc [2] 6b c9 [2] 45 c9 [2] 7a d5 }

  condition:
    any of them
}