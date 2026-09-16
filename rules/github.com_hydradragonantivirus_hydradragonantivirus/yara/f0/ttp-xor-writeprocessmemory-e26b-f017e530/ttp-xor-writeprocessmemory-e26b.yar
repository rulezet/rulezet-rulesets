rule TTP_XOR_WriteProcessMemory_e26b {
  strings:
    $key_e26b = { b5 19 [2] 87 3b [2] 81 0e [2] af 0e [2] 90 12 }

  condition:
    any of them
}