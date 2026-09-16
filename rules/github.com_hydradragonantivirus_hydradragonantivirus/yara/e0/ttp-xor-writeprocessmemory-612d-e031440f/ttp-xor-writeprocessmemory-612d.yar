rule TTP_XOR_WriteProcessMemory_612d {
  strings:
    $key_612d = { 36 5f [2] 04 7d [2] 02 48 [2] 2c 48 [2] 13 54 }

  condition:
    any of them
}