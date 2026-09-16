rule TTP_XOR_WriteProcessMemory_6636 {
  strings:
    $key_6636 = { 31 44 [2] 03 66 [2] 05 53 [2] 2b 53 [2] 14 4f }

  condition:
    any of them
}