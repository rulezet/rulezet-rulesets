rule TTP_XOR_WriteProcessMemory_7fef {
  strings:
    $key_7fef = { 28 9d [2] 1a bf [2] 1c 8a [2] 32 8a [2] 0d 96 }

  condition:
    any of them
}