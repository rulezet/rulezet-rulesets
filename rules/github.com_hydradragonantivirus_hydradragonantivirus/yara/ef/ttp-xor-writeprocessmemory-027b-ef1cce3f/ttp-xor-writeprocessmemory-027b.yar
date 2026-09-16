rule TTP_XOR_WriteProcessMemory_027b {
  strings:
    $key_027b = { 55 09 [2] 67 2b [2] 61 1e [2] 4f 1e [2] 70 02 }

  condition:
    any of them
}