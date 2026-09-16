rule TTP_XOR_WriteProcessMemory_dd4f {
  strings:
    $key_dd4f = { 8a 3d [2] b8 1f [2] be 2a [2] 90 2a [2] af 36 }

  condition:
    any of them
}