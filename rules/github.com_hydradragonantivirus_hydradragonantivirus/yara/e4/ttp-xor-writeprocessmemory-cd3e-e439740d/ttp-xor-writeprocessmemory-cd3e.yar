rule TTP_XOR_WriteProcessMemory_cd3e {
  strings:
    $key_cd3e = { 9a 4c [2] a8 6e [2] ae 5b [2] 80 5b [2] bf 47 }

  condition:
    any of them
}