rule TTP_XOR_WriteProcessMemory_2bfb {
  strings:
    $key_2bfb = { 7c 89 [2] 4e ab [2] 48 9e [2] 66 9e [2] 59 82 }

  condition:
    any of them
}