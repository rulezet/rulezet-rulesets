rule TTP_XOR_WriteProcessMemory_287b {
  strings:
    $key_287b = { 7f 09 [2] 4d 2b [2] 4b 1e [2] 65 1e [2] 5a 02 }

  condition:
    any of them
}