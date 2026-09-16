rule TTP_XOR_WriteProcessMemory_e14f {
  strings:
    $key_e14f = { b6 3d [2] 84 1f [2] 82 2a [2] ac 2a [2] 93 36 }

  condition:
    any of them
}