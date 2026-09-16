rule TTP_XOR_WriteProcessMemory_ca6b {
  strings:
    $key_ca6b = { 9d 19 [2] af 3b [2] a9 0e [2] 87 0e [2] b8 12 }

  condition:
    any of them
}