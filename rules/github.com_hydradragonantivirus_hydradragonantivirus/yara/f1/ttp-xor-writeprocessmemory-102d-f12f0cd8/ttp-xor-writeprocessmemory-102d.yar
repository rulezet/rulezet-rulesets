rule TTP_XOR_WriteProcessMemory_102d {
  strings:
    $key_102d = { 47 5f [2] 75 7d [2] 73 48 [2] 5d 48 [2] 62 54 }

  condition:
    any of them
}