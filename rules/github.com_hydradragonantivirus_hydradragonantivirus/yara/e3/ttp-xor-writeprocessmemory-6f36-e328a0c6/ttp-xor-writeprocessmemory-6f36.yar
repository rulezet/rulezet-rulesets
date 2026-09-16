rule TTP_XOR_WriteProcessMemory_6f36 {
  strings:
    $key_6f36 = { 38 44 [2] 0a 66 [2] 0c 53 [2] 22 53 [2] 1d 4f }

  condition:
    any of them
}