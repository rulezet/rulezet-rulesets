rule TTP_XOR_WriteProcessMemory_e363 {
  strings:
    $key_e363 = { b4 11 [2] 86 33 [2] 80 06 [2] ae 06 [2] 91 1a }

  condition:
    any of them
}