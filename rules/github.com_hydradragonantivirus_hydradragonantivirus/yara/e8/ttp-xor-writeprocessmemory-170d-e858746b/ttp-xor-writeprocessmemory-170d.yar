rule TTP_XOR_WriteProcessMemory_170d {
  strings:
    $key_170d = { 40 7f [2] 72 5d [2] 74 68 [2] 5a 68 [2] 65 74 }

  condition:
    any of them
}