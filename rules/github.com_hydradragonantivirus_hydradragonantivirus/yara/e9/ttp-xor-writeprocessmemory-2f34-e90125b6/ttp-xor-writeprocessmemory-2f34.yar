rule TTP_XOR_WriteProcessMemory_2f34 {
  strings:
    $key_2f34 = { 78 46 [2] 4a 64 [2] 4c 51 [2] 62 51 [2] 5d 4d }

  condition:
    any of them
}