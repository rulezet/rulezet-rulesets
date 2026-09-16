rule TTP_XOR_WriteProcessMemory_664f {
  strings:
    $key_664f = { 31 3d [2] 03 1f [2] 05 2a [2] 2b 2a [2] 14 36 }

  condition:
    any of them
}