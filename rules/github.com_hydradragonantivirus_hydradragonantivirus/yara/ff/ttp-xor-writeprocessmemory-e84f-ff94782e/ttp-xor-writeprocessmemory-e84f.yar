rule TTP_XOR_WriteProcessMemory_e84f {
  strings:
    $key_e84f = { bf 3d [2] 8d 1f [2] 8b 2a [2] a5 2a [2] 9a 36 }

  condition:
    any of them
}