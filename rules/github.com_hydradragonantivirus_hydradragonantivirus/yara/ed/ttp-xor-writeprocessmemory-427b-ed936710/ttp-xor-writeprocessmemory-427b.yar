rule TTP_XOR_WriteProcessMemory_427b {
  strings:
    $key_427b = { 15 09 [2] 27 2b [2] 21 1e [2] 0f 1e [2] 30 02 }

  condition:
    any of them
}