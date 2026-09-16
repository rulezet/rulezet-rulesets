rule TTP_XOR_WriteProcessMemory_2f23 {
  strings:
    $key_2f23 = { 78 51 [2] 4a 73 [2] 4c 46 [2] 62 46 [2] 5d 5a }

  condition:
    any of them
}