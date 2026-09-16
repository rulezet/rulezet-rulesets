rule TTP_XOR_WriteProcessMemory_411b {
  strings:
    $key_411b = { 16 69 [2] 24 4b [2] 22 7e [2] 0c 7e [2] 33 62 }

  condition:
    any of them
}