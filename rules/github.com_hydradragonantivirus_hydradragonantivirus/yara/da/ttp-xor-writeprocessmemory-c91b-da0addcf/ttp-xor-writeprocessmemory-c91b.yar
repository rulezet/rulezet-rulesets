rule TTP_XOR_WriteProcessMemory_c91b {
  strings:
    $key_c91b = { 9e 69 [2] ac 4b [2] aa 7e [2] 84 7e [2] bb 62 }

  condition:
    any of them
}