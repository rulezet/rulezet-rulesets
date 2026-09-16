rule TTP_XOR_WriteProcessMemory_407b {
  strings:
    $key_407b = { 17 09 [2] 25 2b [2] 23 1e [2] 0d 1e [2] 32 02 }

  condition:
    any of them
}