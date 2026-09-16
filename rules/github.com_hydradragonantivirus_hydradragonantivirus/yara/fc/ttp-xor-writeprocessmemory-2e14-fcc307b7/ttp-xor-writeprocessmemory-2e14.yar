rule TTP_XOR_WriteProcessMemory_2e14 {
  strings:
    $key_2e14 = { 79 66 [2] 4b 44 [2] 4d 71 [2] 63 71 [2] 5c 6d }

  condition:
    any of them
}