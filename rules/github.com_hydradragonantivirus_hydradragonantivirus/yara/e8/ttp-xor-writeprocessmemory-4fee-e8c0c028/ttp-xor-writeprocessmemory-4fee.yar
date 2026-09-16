rule TTP_XOR_WriteProcessMemory_4fee {
  strings:
    $key_4fee = { 18 9c [2] 2a be [2] 2c 8b [2] 02 8b [2] 3d 97 }

  condition:
    any of them
}