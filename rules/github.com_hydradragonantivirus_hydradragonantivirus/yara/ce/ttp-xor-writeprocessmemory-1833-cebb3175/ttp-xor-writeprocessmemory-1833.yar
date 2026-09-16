rule TTP_XOR_WriteProcessMemory_1833 {
  strings:
    $key_1833 = { 4f 41 [2] 7d 63 [2] 7b 56 [2] 55 56 [2] 6a 4a }

  condition:
    any of them
}