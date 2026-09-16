rule TTP_XOR_WriteProcessMemory_362d {
  strings:
    $key_362d = { 61 5f [2] 53 7d [2] 55 48 [2] 7b 48 [2] 44 54 }

  condition:
    any of them
}