rule TTP_XOR_WriteProcessMemory_3f36 {
  strings:
    $key_3f36 = { 68 44 [2] 5a 66 [2] 5c 53 [2] 72 53 [2] 4d 4f }

  condition:
    any of them
}