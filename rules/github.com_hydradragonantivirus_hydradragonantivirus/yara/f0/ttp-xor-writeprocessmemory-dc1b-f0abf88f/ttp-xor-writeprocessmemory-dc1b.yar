rule TTP_XOR_WriteProcessMemory_dc1b {
  strings:
    $key_dc1b = { 8b 69 [2] b9 4b [2] bf 7e [2] 91 7e [2] ae 62 }

  condition:
    any of them
}