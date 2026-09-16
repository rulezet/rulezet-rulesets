rule TTP_XOR_WriteProcessMemory_c14f {
  strings:
    $key_c14f = { 96 3d [2] a4 1f [2] a2 2a [2] 8c 2a [2] b3 36 }

  condition:
    any of them
}