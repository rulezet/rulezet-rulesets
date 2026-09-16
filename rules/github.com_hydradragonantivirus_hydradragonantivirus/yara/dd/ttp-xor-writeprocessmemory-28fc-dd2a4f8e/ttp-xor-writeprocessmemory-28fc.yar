rule TTP_XOR_WriteProcessMemory_28fc {
  strings:
    $key_28fc = { 7f 8e [2] 4d ac [2] 4b 99 [2] 65 99 [2] 5a 85 }

  condition:
    any of them
}