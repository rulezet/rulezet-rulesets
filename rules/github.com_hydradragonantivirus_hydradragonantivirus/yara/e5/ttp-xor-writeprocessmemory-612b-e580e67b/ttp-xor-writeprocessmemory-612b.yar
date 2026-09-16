rule TTP_XOR_WriteProcessMemory_612b {
  strings:
    $key_612b = { 36 59 [2] 04 7b [2] 02 4e [2] 2c 4e [2] 13 52 }

  condition:
    any of them
}