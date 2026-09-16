rule TTP_XOR_WriteProcessMemory_4842 {
  strings:
    $key_4842 = { 1f 30 [2] 2d 12 [2] 2b 27 [2] 05 27 [2] 3a 3b }

  condition:
    any of them
}