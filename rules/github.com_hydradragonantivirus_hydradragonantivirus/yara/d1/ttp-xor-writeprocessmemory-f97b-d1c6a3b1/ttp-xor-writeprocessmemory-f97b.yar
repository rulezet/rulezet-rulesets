rule TTP_XOR_WriteProcessMemory_f97b {
  strings:
    $key_f97b = { ae 09 [2] 9c 2b [2] 9a 1e [2] b4 1e [2] 8b 02 }

  condition:
    any of them
}