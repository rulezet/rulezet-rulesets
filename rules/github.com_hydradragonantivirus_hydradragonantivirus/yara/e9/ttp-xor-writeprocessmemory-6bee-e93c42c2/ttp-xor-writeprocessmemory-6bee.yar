rule TTP_XOR_WriteProcessMemory_6bee {
  strings:
    $key_6bee = { 3c 9c [2] 0e be [2] 08 8b [2] 26 8b [2] 19 97 }

  condition:
    any of them
}