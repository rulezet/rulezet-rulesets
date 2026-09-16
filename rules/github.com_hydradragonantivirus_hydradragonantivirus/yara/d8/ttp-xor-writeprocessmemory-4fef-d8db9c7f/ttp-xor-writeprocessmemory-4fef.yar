rule TTP_XOR_WriteProcessMemory_4fef {
  strings:
    $key_4fef = { 18 9d [2] 2a bf [2] 2c 8a [2] 02 8a [2] 3d 96 }

  condition:
    any of them
}