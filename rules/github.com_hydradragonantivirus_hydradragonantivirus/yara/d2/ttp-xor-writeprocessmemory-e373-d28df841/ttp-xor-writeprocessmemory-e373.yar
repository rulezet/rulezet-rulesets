rule TTP_XOR_WriteProcessMemory_e373 {
  strings:
    $key_e373 = { b4 01 [2] 86 23 [2] 80 16 [2] ae 16 [2] 91 0a }

  condition:
    any of them
}