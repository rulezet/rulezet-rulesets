rule TTP_XOR_WriteProcessMemory_c54f {
  strings:
    $key_c54f = { 92 3d [2] a0 1f [2] a6 2a [2] 88 2a [2] b7 36 }

  condition:
    any of them
}