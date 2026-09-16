rule TTP_XOR_WriteProcessMemory_19f4 {
  strings:
    $key_19f4 = { 4e 86 [2] 7c a4 [2] 7a 91 [2] 54 91 [2] 6b 8d }

  condition:
    any of them
}