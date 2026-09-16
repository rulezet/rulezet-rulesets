rule TTP_XOR_WriteProcessMemory_abbe {
  strings:
    $key_abbe = { fc cc [2] ce ee [2] c8 db [2] e6 db [2] d9 c7 }

  condition:
    any of them
}