rule TTP_XOR_WriteProcessMemory_2842 {
  strings:
    $key_2842 = { 7f 30 [2] 4d 12 [2] 4b 27 [2] 65 27 [2] 5a 3b }

  condition:
    any of them
}