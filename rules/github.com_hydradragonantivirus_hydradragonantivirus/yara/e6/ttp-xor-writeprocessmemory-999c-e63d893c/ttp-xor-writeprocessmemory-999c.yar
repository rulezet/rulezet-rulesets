rule TTP_XOR_WriteProcessMemory_999c {
  strings:
    $key_999c = { ce ee [2] fc cc [2] fa f9 [2] d4 f9 [2] eb e5 }

  condition:
    any of them
}