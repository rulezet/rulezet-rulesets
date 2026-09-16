rule TTP_XOR_WriteProcessMemory_012b {
  strings:
    $key_012b = { 56 59 [2] 64 7b [2] 62 4e [2] 4c 4e [2] 73 52 }

  condition:
    any of them
}