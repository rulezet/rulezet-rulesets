rule TTP_XOR_WriteProcessMemory_dc6b {
  strings:
    $key_dc6b = { 8b 19 [2] b9 3b [2] bf 0e [2] 91 0e [2] ae 12 }

  condition:
    any of them
}