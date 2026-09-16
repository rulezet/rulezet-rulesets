rule TTP_XOR_WriteProcessMemory_e34b {
  strings:
    $key_e34b = { b4 39 [2] 86 1b [2] 80 2e [2] ae 2e [2] 91 32 }

  condition:
    any of them
}