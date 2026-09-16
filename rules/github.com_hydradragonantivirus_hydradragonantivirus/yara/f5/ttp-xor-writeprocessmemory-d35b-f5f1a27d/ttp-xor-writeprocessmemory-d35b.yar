rule TTP_XOR_WriteProcessMemory_d35b {
  strings:
    $key_d35b = { 84 29 [2] b6 0b [2] b0 3e [2] 9e 3e [2] a1 22 }

  condition:
    any of them
}