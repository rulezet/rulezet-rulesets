rule TTP_XOR_WriteProcessMemory_7bee {
  strings:
    $key_7bee = { 2c 9c [2] 1e be [2] 18 8b [2] 36 8b [2] 09 97 }

  condition:
    any of them
}