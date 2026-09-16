rule TTP_XOR_WriteProcessMemory_5efa {
  strings:
    $key_5efa = { 09 88 [2] 3b aa [2] 3d 9f [2] 13 9f [2] 2c 83 }

  condition:
    any of them
}