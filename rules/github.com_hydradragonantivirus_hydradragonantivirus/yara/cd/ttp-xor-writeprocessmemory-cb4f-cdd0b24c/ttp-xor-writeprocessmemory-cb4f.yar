rule TTP_XOR_WriteProcessMemory_cb4f {
  strings:
    $key_cb4f = { 9c 3d [2] ae 1f [2] a8 2a [2] 86 2a [2] b9 36 }

  condition:
    any of them
}