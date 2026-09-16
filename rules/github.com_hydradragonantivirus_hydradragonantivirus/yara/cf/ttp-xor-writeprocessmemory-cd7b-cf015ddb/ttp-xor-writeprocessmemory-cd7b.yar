rule TTP_XOR_WriteProcessMemory_cd7b {
  strings:
    $key_cd7b = { 9a 09 [2] a8 2b [2] ae 1e [2] 80 1e [2] bf 02 }

  condition:
    any of them
}