rule TTP_XOR_WriteProcessMemory_2724 {
  strings:
    $key_2724 = { 70 56 [2] 42 74 [2] 44 41 [2] 6a 41 [2] 55 5d }

  condition:
    any of them
}