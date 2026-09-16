rule TTP_XOR_WriteProcessMemory_06be {
  strings:
    $key_06be = { 51 cc [2] 63 ee [2] 65 db [2] 4b db [2] 74 c7 }

  condition:
    any of them
}