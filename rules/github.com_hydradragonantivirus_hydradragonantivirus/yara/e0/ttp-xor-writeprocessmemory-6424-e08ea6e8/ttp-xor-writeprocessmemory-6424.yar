rule TTP_XOR_WriteProcessMemory_6424 {
  strings:
    $key_6424 = { 33 56 [2] 01 74 [2] 07 41 [2] 29 41 [2] 16 5d }

  condition:
    any of them
}