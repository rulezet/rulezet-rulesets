rule TTP_XOR_WriteProcessMemory_c64f {
  strings:
    $key_c64f = { 91 3d [2] a3 1f [2] a5 2a [2] 8b 2a [2] b4 36 }

  condition:
    any of them
}