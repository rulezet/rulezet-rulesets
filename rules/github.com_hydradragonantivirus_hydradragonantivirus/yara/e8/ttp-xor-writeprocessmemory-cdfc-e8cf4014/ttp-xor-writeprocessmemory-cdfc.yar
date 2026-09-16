rule TTP_XOR_WriteProcessMemory_cdfc {
  strings:
    $key_cdfc = { 9a 8e [2] a8 ac [2] ae 99 [2] 80 99 [2] bf 85 }

  condition:
    any of them
}