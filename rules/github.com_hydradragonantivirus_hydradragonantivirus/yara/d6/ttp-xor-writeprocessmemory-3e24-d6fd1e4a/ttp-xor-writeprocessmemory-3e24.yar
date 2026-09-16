rule TTP_XOR_WriteProcessMemory_3e24 {
  strings:
    $key_3e24 = { 69 56 [2] 5b 74 [2] 5d 41 [2] 73 41 [2] 4c 5d }

  condition:
    any of them
}