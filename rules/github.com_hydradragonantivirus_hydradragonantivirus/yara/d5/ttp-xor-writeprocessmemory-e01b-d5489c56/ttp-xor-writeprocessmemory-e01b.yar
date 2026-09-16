rule TTP_XOR_WriteProcessMemory_e01b {
  strings:
    $key_e01b = { b7 69 [2] 85 4b [2] 83 7e [2] ad 7e [2] 92 62 }

  condition:
    any of them
}