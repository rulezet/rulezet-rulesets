rule TTP_XOR_WriteProcessMemory_7f11 {
  strings:
    $key_7f11 = { 28 63 [2] 1a 41 [2] 1c 74 [2] 32 74 [2] 0d 68 }

  condition:
    any of them
}