rule TTP_XOR_WriteProcessMemory_0047 {
  strings:
    $key_0047 = { 57 35 [2] 65 17 [2] 63 22 [2] 4d 22 [2] 72 3e }

  condition:
    any of them
}