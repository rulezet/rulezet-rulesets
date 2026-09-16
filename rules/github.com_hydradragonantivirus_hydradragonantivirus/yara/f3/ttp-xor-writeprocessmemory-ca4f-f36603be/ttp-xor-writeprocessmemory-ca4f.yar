rule TTP_XOR_WriteProcessMemory_ca4f {
  strings:
    $key_ca4f = { 9d 3d [2] af 1f [2] a9 2a [2] 87 2a [2] b8 36 }

  condition:
    any of them
}