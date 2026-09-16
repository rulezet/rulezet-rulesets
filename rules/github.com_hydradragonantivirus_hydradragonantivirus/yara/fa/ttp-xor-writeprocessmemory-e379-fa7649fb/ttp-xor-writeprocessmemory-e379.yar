rule TTP_XOR_WriteProcessMemory_e379 {
  strings:
    $key_e379 = { b4 0b [2] 86 29 [2] 80 1c [2] ae 1c [2] 91 00 }

  condition:
    any of them
}