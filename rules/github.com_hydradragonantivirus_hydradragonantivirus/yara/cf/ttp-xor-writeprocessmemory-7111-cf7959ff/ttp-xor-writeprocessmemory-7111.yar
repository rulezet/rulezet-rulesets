rule TTP_XOR_WriteProcessMemory_7111 {
  strings:
    $key_7111 = { 26 63 [2] 14 41 [2] 12 74 [2] 3c 74 [2] 03 68 }

  condition:
    any of them
}