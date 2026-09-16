rule TTP_XOR_WriteProcessMemory_3f20 {
  strings:
    $key_3f20 = { 68 52 [2] 5a 70 [2] 5c 45 [2] 72 45 [2] 4d 59 }

  condition:
    any of them
}