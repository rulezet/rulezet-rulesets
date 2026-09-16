rule TTP_XOR_WriteProcessMemory_decc {
  strings:
    $key_decc = { 89 be [2] bb 9c [2] bd a9 [2] 93 a9 [2] ac b5 }

  condition:
    any of them
}