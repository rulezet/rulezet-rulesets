rule TTP_XOR_WriteProcessMemory_8dbe {
  strings:
    $key_8dbe = { da cc [2] e8 ee [2] ee db [2] c0 db [2] ff c7 }

  condition:
    any of them
}