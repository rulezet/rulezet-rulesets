rule TTP_XOR_WriteProcessMemory_2942 {
  strings:
    $key_2942 = { 7e 30 [2] 4c 12 [2] 4a 27 [2] 64 27 [2] 5b 3b }

  condition:
    any of them
}