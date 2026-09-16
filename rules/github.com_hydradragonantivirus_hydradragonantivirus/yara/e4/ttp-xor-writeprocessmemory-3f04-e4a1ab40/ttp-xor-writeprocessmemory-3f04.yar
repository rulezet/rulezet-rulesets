rule TTP_XOR_WriteProcessMemory_3f04 {
  strings:
    $key_3f04 = { 68 76 [2] 5a 54 [2] 5c 61 [2] 72 61 [2] 4d 7d }

  condition:
    any of them
}