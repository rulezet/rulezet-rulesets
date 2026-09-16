rule TTP_XOR_WriteProcessMemory_ca0b {
  strings:
    $key_ca0b = { 9d 79 [2] af 5b [2] a9 6e [2] 87 6e [2] b8 72 }

  condition:
    any of them
}