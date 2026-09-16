rule TTP_XOR_WriteProcessMemory_f96b {
  strings:
    $key_f96b = { ae 19 [2] 9c 3b [2] 9a 0e [2] b4 0e [2] 8b 12 }

  condition:
    any of them
}