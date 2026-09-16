rule TTP_XOR_WriteProcessMemory_691b {
  strings:
    $key_691b = { 3e 69 [2] 0c 4b [2] 0a 7e [2] 24 7e [2] 1b 62 }

  condition:
    any of them
}