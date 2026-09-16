rule TTP_XOR_WriteProcessMemory_4958 {
  strings:
    $key_4958 = { 1e 2a [2] 2c 08 [2] 2a 3d [2] 04 3d [2] 3b 21 }

  condition:
    any of them
}