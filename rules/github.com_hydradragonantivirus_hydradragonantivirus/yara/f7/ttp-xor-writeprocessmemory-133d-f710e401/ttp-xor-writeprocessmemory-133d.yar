rule TTP_XOR_WriteProcessMemory_133d {
  strings:
    $key_133d = { 44 4f [2] 76 6d [2] 70 58 [2] 5e 58 [2] 61 44 }

  condition:
    any of them
}