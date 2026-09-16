rule TTP_XOR_WriteProcessMemory_e33c {
  strings:
    $key_e33c = { b4 4e [2] 86 6c [2] 80 59 [2] ae 59 [2] 91 45 }

  condition:
    any of them
}