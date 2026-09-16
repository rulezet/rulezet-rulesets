rule TTP_XOR_WriteProcessMemory_09f4 {
  strings:
    $key_09f4 = { 5e 86 [2] 6c a4 [2] 6a 91 [2] 44 91 [2] 7b 8d }

  condition:
    any of them
}