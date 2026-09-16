rule TTP_XOR_WriteProcessMemory_7f24 {
  strings:
    $key_7f24 = { 28 56 [2] 1a 74 [2] 1c 41 [2] 32 41 [2] 0d 5d }

  condition:
    any of them
}