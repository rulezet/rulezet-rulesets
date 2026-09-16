rule TTP_XOR_WriteProcessMemory_6aef {
  strings:
    $key_6aef = { 3d 9d [2] 0f bf [2] 09 8a [2] 27 8a [2] 18 96 }

  condition:
    any of them
}