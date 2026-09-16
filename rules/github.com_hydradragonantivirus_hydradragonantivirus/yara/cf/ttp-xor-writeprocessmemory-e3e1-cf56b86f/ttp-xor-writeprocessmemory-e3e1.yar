rule TTP_XOR_WriteProcessMemory_e3e1 {
  strings:
    $key_e3e1 = { b4 93 [2] 86 b1 [2] 80 84 [2] ae 84 [2] 91 98 }

  condition:
    any of them
}