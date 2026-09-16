rule TTP_XOR_WriteProcessMemory_3feb {
  strings:
    $key_3feb = { 68 99 [2] 5a bb [2] 5c 8e [2] 72 8e [2] 4d 92 }

  condition:
    any of them
}