rule TTP_XOR_WriteProcessMemory_cd5c {
  strings:
    $key_cd5c = { 9a 2e [2] a8 0c [2] ae 39 [2] 80 39 [2] bf 25 }

  condition:
    any of them
}