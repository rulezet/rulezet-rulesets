rule TTP_XOR_WriteProcessMemory_ee6b {
  strings:
    $key_ee6b = { b9 19 [2] 8b 3b [2] 8d 0e [2] a3 0e [2] 9c 12 }

  condition:
    any of them
}