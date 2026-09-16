rule TTP_XOR_WriteProcessMemory_18f4 {
  strings:
    $key_18f4 = { 4f 86 [2] 7d a4 [2] 7b 91 [2] 55 91 [2] 6a 8d }

  condition:
    any of them
}