rule TTP_XOR_WriteProcessMemory_071d {
  strings:
    $key_071d = { 50 6f [2] 62 4d [2] 64 78 [2] 4a 78 [2] 75 64 }

  condition:
    any of them
}