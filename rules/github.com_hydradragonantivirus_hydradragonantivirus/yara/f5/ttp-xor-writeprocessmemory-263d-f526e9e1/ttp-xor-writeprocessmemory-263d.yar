rule TTP_XOR_WriteProcessMemory_263d {
  strings:
    $key_263d = { 71 4f [2] 43 6d [2] 45 58 [2] 6b 58 [2] 54 44 }

  condition:
    any of them
}