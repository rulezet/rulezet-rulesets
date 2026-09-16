rule TTP_XOR_WriteProcessMemory_58be {
  strings:
    $key_58be = { 0f cc [2] 3d ee [2] 3b db [2] 15 db [2] 2a c7 }

  condition:
    any of them
}