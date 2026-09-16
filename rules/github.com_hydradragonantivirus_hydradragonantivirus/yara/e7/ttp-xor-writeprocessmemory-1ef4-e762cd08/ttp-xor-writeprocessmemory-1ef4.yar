rule TTP_XOR_WriteProcessMemory_1ef4 {
  strings:
    $key_1ef4 = { 49 86 [2] 7b a4 [2] 7d 91 [2] 53 91 [2] 6c 8d }

  condition:
    any of them
}