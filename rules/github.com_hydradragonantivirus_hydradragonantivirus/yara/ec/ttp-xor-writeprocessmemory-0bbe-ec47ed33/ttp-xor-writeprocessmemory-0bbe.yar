rule TTP_XOR_WriteProcessMemory_0bbe {
  strings:
    $key_0bbe = { 5c cc [2] 6e ee [2] 68 db [2] 46 db [2] 79 c7 }

  condition:
    any of them
}