rule TTP_XOR_WriteProcessMemory_3f11 {
  strings:
    $key_3f11 = { 68 63 [2] 5a 41 [2] 5c 74 [2] 72 74 [2] 4d 68 }

  condition:
    any of them
}