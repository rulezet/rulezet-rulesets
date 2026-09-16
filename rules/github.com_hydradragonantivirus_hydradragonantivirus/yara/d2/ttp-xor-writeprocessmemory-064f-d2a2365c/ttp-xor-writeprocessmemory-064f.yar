rule TTP_XOR_WriteProcessMemory_064f {
  strings:
    $key_064f = { 51 3d [2] 63 1f [2] 65 2a [2] 4b 2a [2] 74 36 }

  condition:
    any of them
}