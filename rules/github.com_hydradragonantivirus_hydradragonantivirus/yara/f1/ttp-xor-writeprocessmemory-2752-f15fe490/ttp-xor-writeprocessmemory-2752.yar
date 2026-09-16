rule TTP_XOR_WriteProcessMemory_2752 {
  strings:
    $key_2752 = { 70 20 [2] 42 02 [2] 44 37 [2] 6a 37 [2] 55 2b }

  condition:
    any of them
}