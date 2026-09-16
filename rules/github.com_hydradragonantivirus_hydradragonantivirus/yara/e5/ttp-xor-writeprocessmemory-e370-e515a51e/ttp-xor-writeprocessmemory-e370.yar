rule TTP_XOR_WriteProcessMemory_e370 {
  strings:
    $key_e370 = { b4 02 [2] 86 20 [2] 80 15 [2] ae 15 [2] 91 09 }

  condition:
    any of them
}