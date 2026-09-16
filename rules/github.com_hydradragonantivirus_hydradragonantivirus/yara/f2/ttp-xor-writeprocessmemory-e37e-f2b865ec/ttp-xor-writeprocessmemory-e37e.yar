rule TTP_XOR_WriteProcessMemory_e37e {
  strings:
    $key_e37e = { b4 0c [2] 86 2e [2] 80 1b [2] ae 1b [2] 91 07 }

  condition:
    any of them
}