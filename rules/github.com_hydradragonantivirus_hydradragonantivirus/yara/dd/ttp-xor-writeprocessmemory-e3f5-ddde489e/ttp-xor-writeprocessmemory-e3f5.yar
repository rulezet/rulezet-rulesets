rule TTP_XOR_WriteProcessMemory_e3f5 {
  strings:
    $key_e3f5 = { b4 87 [2] 86 a5 [2] 80 90 [2] ae 90 [2] 91 8c }

  condition:
    any of them
}