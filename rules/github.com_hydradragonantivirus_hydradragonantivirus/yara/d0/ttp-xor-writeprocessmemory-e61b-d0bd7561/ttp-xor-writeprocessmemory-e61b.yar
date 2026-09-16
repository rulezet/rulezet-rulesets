rule TTP_XOR_WriteProcessMemory_e61b {
  strings:
    $key_e61b = { b1 69 [2] 83 4b [2] 85 7e [2] ab 7e [2] 94 62 }

  condition:
    any of them
}