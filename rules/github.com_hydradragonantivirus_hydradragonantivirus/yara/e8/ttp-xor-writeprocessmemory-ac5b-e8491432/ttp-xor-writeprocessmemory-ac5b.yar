rule TTP_XOR_WriteProcessMemory_ac5b {
  strings:
    $key_ac5b = { fb 29 [2] c9 0b [2] cf 3e [2] e1 3e [2] de 22 }

  condition:
    any of them
}