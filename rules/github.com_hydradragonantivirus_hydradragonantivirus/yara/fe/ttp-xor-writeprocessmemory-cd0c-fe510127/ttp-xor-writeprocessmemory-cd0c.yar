rule TTP_XOR_WriteProcessMemory_cd0c {
  strings:
    $key_cd0c = { 9a 7e [2] a8 5c [2] ae 69 [2] 80 69 [2] bf 75 }

  condition:
    any of them
}