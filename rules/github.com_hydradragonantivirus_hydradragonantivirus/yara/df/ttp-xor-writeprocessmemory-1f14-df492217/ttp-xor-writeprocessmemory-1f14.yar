rule TTP_XOR_WriteProcessMemory_1f14 {
  strings:
    $key_1f14 = { 48 66 [2] 7a 44 [2] 7c 71 [2] 52 71 [2] 6d 6d }

  condition:
    any of them
}