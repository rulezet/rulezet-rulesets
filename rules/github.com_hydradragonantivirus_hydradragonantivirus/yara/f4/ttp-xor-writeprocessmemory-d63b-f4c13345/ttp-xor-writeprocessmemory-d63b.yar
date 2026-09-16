rule TTP_XOR_WriteProcessMemory_d63b {
  strings:
    $key_d63b = { 81 49 [2] b3 6b [2] b5 5e [2] 9b 5e [2] a4 42 }

  condition:
    any of them
}