rule TTP_XOR_WriteProcessMemory_6876 {
  strings:
    $key_6876 = { 3f 04 [2] 0d 26 [2] 0b 13 [2] 25 13 [2] 1a 0f }

  condition:
    any of them
}