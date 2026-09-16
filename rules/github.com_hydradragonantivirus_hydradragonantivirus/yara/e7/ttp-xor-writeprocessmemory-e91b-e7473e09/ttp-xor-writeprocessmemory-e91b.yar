rule TTP_XOR_WriteProcessMemory_e91b {
  strings:
    $key_e91b = { be 69 [2] 8c 4b [2] 8a 7e [2] a4 7e [2] 9b 62 }

  condition:
    any of them
}