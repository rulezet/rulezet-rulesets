rule TTP_XOR_WriteProcessMemory_461d {
  strings:
    $key_461d = { 11 6f [2] 23 4d [2] 25 78 [2] 0b 78 [2] 34 64 }

  condition:
    any of them
}