rule TTP_XOR_WriteProcessMemory_cd7e {
  strings:
    $key_cd7e = { 9a 0c [2] a8 2e [2] ae 1b [2] 80 1b [2] bf 07 }

  condition:
    any of them
}