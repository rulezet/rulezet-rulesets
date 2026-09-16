rule TTP_XOR_WriteProcessMemory_4aef {
  strings:
    $key_4aef = { 1d 9d [2] 2f bf [2] 29 8a [2] 07 8a [2] 38 96 }

  condition:
    any of them
}