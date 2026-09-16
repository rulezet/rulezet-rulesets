rule TTP_XOR_WriteProcessMemory_615b {
  strings:
    $key_615b = { 36 29 [2] 04 0b [2] 02 3e [2] 2c 3e [2] 13 22 }

  condition:
    any of them
}