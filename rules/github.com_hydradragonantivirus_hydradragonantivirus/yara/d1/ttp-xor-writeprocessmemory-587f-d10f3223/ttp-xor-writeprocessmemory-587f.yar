rule TTP_XOR_WriteProcessMemory_587f {
  strings:
    $key_587f = { 0f 0d [2] 3d 2f [2] 3b 1a [2] 15 1a [2] 2a 06 }

  condition:
    any of them
}