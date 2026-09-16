rule TTP_XOR_WriteProcessMemory_1ff4 {
  strings:
    $key_1ff4 = { 48 86 [2] 7a a4 [2] 7c 91 [2] 52 91 [2] 6d 8d }

  condition:
    any of them
}