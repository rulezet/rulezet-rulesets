rule TTP_XOR_WriteProcessMemory_5abe {
  strings:
    $key_5abe = { 0d cc [2] 3f ee [2] 39 db [2] 17 db [2] 28 c7 }

  condition:
    any of them
}