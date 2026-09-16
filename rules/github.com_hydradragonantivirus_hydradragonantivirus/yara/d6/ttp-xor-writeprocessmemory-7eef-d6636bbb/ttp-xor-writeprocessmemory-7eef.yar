rule TTP_XOR_WriteProcessMemory_7eef {
  strings:
    $key_7eef = { 29 9d [2] 1b bf [2] 1d 8a [2] 33 8a [2] 0c 96 }

  condition:
    any of them
}