rule TTP_XOR_WriteProcessMemory_1abe {
  strings:
    $key_1abe = { 4d cc [2] 7f ee [2] 79 db [2] 57 db [2] 68 c7 }

  condition:
    any of them
}