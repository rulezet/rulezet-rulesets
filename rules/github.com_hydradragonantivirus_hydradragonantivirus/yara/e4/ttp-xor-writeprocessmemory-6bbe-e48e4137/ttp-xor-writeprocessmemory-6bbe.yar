rule TTP_XOR_WriteProcessMemory_6bbe {
  strings:
    $key_6bbe = { 3c cc [2] 0e ee [2] 08 db [2] 26 db [2] 19 c7 }

  condition:
    any of them
}