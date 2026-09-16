rule TTP_XOR_WriteProcessMemory_cd6e {
  strings:
    $key_cd6e = { 9a 1c [2] a8 3e [2] ae 0b [2] 80 0b [2] bf 17 }

  condition:
    any of them
}