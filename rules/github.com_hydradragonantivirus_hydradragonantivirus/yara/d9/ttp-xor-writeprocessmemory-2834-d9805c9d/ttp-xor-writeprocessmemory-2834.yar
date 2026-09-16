rule TTP_XOR_WriteProcessMemory_2834 {
  strings:
    $key_2834 = { 7f 46 [2] 4d 64 [2] 4b 51 [2] 65 51 [2] 5a 4d }

  condition:
    any of them
}