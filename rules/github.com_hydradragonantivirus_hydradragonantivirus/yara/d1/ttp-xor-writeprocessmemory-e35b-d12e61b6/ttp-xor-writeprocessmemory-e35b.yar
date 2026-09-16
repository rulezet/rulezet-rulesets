rule TTP_XOR_WriteProcessMemory_e35b {
  strings:
    $key_e35b = { b4 29 [2] 86 0b [2] 80 3e [2] ae 3e [2] 91 22 }

  condition:
    any of them
}