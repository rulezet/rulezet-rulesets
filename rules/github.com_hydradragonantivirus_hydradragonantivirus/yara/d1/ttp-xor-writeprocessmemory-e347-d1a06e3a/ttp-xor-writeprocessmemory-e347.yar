rule TTP_XOR_WriteProcessMemory_e347 {
  strings:
    $key_e347 = { b4 35 [2] 86 17 [2] 80 22 [2] ae 22 [2] 91 3e }

  condition:
    any of them
}