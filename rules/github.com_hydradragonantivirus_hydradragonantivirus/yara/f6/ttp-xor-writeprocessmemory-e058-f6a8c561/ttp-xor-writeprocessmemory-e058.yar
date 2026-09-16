rule TTP_XOR_WriteProcessMemory_e058 {
  strings:
    $key_e058 = { b7 2a [2] 85 08 [2] 83 3d [2] ad 3d [2] 92 21 }

  condition:
    any of them
}