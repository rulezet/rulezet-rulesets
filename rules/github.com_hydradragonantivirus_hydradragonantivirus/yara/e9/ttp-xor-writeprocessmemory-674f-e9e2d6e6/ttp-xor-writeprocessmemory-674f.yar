rule TTP_XOR_WriteProcessMemory_674f {
  strings:
    $key_674f = { 30 3d [2] 02 1f [2] 04 2a [2] 2a 2a [2] 15 36 }

  condition:
    any of them
}