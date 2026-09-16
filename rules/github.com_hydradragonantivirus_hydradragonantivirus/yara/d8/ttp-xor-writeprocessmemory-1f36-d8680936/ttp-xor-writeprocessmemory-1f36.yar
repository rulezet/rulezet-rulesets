rule TTP_XOR_WriteProcessMemory_1f36 {
  strings:
    $key_1f36 = { 48 44 [2] 7a 66 [2] 7c 53 [2] 52 53 [2] 6d 4f }

  condition:
    any of them
}