rule TTP_XOR_WriteProcessMemory_1f11 {
  strings:
    $key_1f11 = { 48 63 [2] 7a 41 [2] 7c 74 [2] 52 74 [2] 6d 68 }

  condition:
    any of them
}