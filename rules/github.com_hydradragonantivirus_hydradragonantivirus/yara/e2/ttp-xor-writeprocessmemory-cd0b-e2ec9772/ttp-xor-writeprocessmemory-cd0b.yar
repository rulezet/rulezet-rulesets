rule TTP_XOR_WriteProcessMemory_cd0b {
  strings:
    $key_cd0b = { 9a 79 [2] a8 5b [2] ae 6e [2] 80 6e [2] bf 72 }

  condition:
    any of them
}