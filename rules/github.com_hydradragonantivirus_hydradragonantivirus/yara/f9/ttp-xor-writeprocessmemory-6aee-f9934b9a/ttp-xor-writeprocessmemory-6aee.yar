rule TTP_XOR_WriteProcessMemory_6aee {
  strings:
    $key_6aee = { 3d 9c [2] 0f be [2] 09 8b [2] 27 8b [2] 18 97 }

  condition:
    any of them
}