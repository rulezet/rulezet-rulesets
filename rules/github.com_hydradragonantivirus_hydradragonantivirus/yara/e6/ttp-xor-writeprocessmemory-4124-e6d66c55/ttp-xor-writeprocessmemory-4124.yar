rule TTP_XOR_WriteProcessMemory_4124 {
  strings:
    $key_4124 = { 16 56 [2] 24 74 [2] 22 41 [2] 0c 41 [2] 33 5d }

  condition:
    any of them
}